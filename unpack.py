#!/usr/bin/env python3

from collections.abc import Buffer
import json
import os


ECC_WINDOW = 0x30000   # bootcode do_ecc reserves this for the parity stream
GAP_BYTES = 2          # vendor "gap" between squashfs end and parity stream
PTR_BYTES = 4          # little-endian u32 rootfs offset


def unpack(img: Buffer):
    img_ = memoryview(img)
    if img_[:4] != memoryview(b'cr6c'):
        raise ValueError(f'not a cr6c image: {img_[:4]!r}')
    if len(img_) < 64 + GAP_BYTES + ECC_WINDOW + PTR_BYTES:
        raise ValueError(f'image too small: {len(img_)} bytes')

    payload_len = int.from_bytes(img_[12:16], 'big')
    if payload_len < GAP_BYTES + ECC_WINDOW + PTR_BYTES:
        raise ValueError('header.len too small')
    if len(img_) < 64 + payload_len:
        raise ValueError(f'truncated payload: {len(img_) - 64} < {payload_len}')

    payload = img_[64:64 + payload_len]
    tail_off = int.from_bytes(payload[-PTR_BYTES:], 'little')
    base_off = int.from_bytes(
        payload[payload_len - ECC_WINDOW - PTR_BYTES:payload_len - ECC_WINDOW],
        'little')
    if img_[tail_off:tail_off + 4] == memoryview(b'hsqs'):
        rootfs_off = tail_off
        kernel_type = 1
    elif img_[base_off:base_off + 4] == memoryview(b'hsqs'):
        rootfs_off = base_off
        kernel_type = 0
    else:
        raise ValueError('cannot find rootfs offset')

    data_end = 64 + payload_len - ECC_WINDOW - PTR_BYTES - GAP_BYTES

    meta = {
        'load_addr': int.from_bytes(img_[4:8], 'big'),
        'burn_addr': int.from_bytes(img_[8:12], 'big'),
        'name': bytes(img_[32:48]).rstrip(b'\0').decode(),
        'version': bytes(img_[48:60]).rstrip(b'\0').decode(),
        'build': int.from_bytes(img_[60:64], 'little'),
        'type': kernel_type,
    }
    return meta, img_[64:rootfs_off], img_[rootfs_off:data_end]


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description='Split a Netcore MG1200AC firmware into kernel and rootfs.')
    parser.add_argument('input', help='input file')
    parser.add_argument('outdir', help='output directory')
    args = parser.parse_args()

    try:
        with open(args.input, 'rb') as f:
            data = f.read()
    except OSError as e:
        parser.error(f"cannot read '{args.input}': {e}")

    try:
        meta, kernel, rootfs = unpack(data)
    except ValueError as e:
        parser.error(str(e))

    os.makedirs(args.outdir, exist_ok=True)
    with open(os.path.join(args.outdir, 'header.json'), 'w') as f:
        json.dump(meta, f, indent=2)
    with open(os.path.join(args.outdir, 'kernel.bin'), 'wb') as f:
        f.write(kernel)
    with open(os.path.join(args.outdir, 'rootfs.squashfs'), 'wb') as f:
        f.write(rootfs)

    print(f"unpacked {args.input} into {args.outdir}/")
    print(f"  load 0x{meta['load_addr']:x}, burn 0x{meta['burn_addr']:x}")
    print(f"  name {meta['name']}, version {meta['version']}")
    print(f"  kernel      {len(kernel):#x} bytes")
    print(f"  rootfs      {len(rootfs):#x} bytes")
    print(f"  type        {'normal' if meta['type'] == 0 else 'glitched'}")
    return 0


if __name__ == '__main__':
    exit(main())
