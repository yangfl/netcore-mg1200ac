#!/usr/bin/env python3

from collections.abc import Buffer

import json
import os
import sys

sys.path.append(os.path.dirname(__file__))

from mkfenglianimage import fenglian_image, smartmedia_eccs


ECC_WINDOW = 0x30000   # bootcode do_ecc reserves this for the parity stream
GAP_BYTES = 2          # vendor "gap" between squashfs end and parity stream
PTR_BYTES = 4          # little-endian u32 rootfs offset
BURN_END = 0xB00000    # Kernel_RootFS partition end (burn addr 0x30000)


def build_payload(
        kernel: Buffer, rootfs: Buffer, kernel_type: int,
        ecc: bool = False) -> tuple[bytes, int]:
    payload_len = len(memoryview(kernel)) + len(memoryview(rootfs)) + \
        GAP_BYTES + PTR_BYTES + ECC_WINDOW
    if 0x30000 + 64 + payload_len > BURN_END:
        raise ValueError(
            f'image too big: burn to 0x{0x30000 + 64 + payload_len:#x} exceeds '
            f'Kernel_RootFS end 0x{BURN_END:#x}')

    rootfs_off = (len(memoryview(kernel)) + 64).to_bytes(4, 'little')
    parts: list[Buffer] = [kernel, rootfs, b'\0' * GAP_BYTES]
    if kernel_type == 0:
        parts.append(rootfs_off)
        if ecc:
            parts = [b''.join(parts)]
            parities = smartmedia_eccs(parts[0])
            parts.append(parities)
    elif kernel_type == 1:
        if not ecc:
            payload_len -= ECC_WINDOW
        else:
            parts = [b''.join(parts)]
            parities = smartmedia_eccs(parts[0])
            parts.append(parities)
            if len(parities) < ECC_WINDOW:
                parts.append(b'\0' * (ECC_WINDOW - len(parities)))
        parts.append(rootfs_off)
    else:
        raise ValueError(f'unknown kernel type {kernel_type}')

    payload = b''.join(parts)
    return payload, payload_len


def build(
        meta: dict, kernel: Buffer, rootfs: Buffer, ecc: bool = False) -> bytes:
    payload, payload_len = build_payload(kernel, rootfs, meta['type'], ecc)
    image = fenglian_image(
        payload, load_addr=meta['load_addr'], burn_addr=meta['burn_addr'],
        payload_len=payload_len,
        name=meta['name'].encode(), version=meta['version'].encode(),
        build=int(meta.get('build', 0)))
    return image


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description='Repack Netcore MG1200AC firmwares.')
    parser.add_argument(
        '-j', '--header', required=True,
        help='header.json')
    parser.add_argument(
        '-k', '--kernel', required=True,
        help='kernel.bin')
    parser.add_argument(
        '-r', '--rootfs', required=True,
        help='rootfs.squashfs')
    parser.add_argument(
        '--ecc', action='store_true',
        help='calculate and fill ECC parity stream, not required for a '
        'bootable image')
    parser.add_argument('output', help='output file')
    args = parser.parse_args()

    try:
        with open(args.header) as f:
            meta = json.load(f)
        with open(args.kernel, 'rb') as f:
            kernel = f.read()
        with open(args.rootfs, 'rb') as f:
            rootfs = f.read()
    except (OSError, json.JSONDecodeError) as e:
        parser.error(f'cannot read inputs: {e}')

    if rootfs[:4] != b'hsqs':
        parser.error(f'rootfs is not a squashfs: {rootfs[:4]!r}')

    image = build(meta, kernel, rootfs, args.ecc)
    with open(args.output, 'wb') as f:
        f.write(image)
    print(f'wrote {args.output}: {len(image)} bytes')
    return 0


if __name__ == '__main__':
    exit(main())
