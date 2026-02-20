#!/usr/bin/env python3

"""
RTL819x boot code `IMG_HEADER_T` from boot/init/rtk.h.

#define SIG_LEN 4

typedef struct __attribute__((__packed__)) _img_header_ {
  uint8_t signature[SIG_LEN];
  uint32_t startAddr;
  uint32_t burnAddr;
  uint32_t len;
} IMG_HEADER_T;
"""

import argparse
import os
import sys
from typing import BinaryIO


SIGNATURES = {
    'linux': 'csys',
    'linux_root': 'csro',
    'root': 'root',
    'web': 'webp',
    'linux_8198': 'cs6c',
    'linux_root_8198': 'cr6c',
    'root_8198': 'r6cr',
    'web_8198': 'w6cg',
    'cmd': 'cmd ',
    'boot': 'boot',
    'iram': 'iram',
    'all': 'ALL1',
    'all_unchecked': 'ALL2',
}


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-T', '--type', type=str, default='fw',
        help='image type, pass -h to see the list (default: fw)')
    parser.add_argument(
        '-a', '--load-addr', type=int, default=0x80a00000,
        help='image load address (default: 0x80a00000)')
    parser.add_argument(
        '-b', '--burn-addr', type=int, default=0x30000,
        help='flash burn offset (default: 0x30000)')
    parser.add_argument(
        '-l', '--len', type=int, default=None,
        help='image length (default: input file length)')
    parser.add_argument(
        '-d', '--input', type=argparse.FileType('rb'),
        help='input file')
    parser.add_argument('output', type=str, help='output file')

    args = parser.parse_args()

    img_sig: str
    if args.type in SIGNATURES:
        img_sig = SIGNATURES[args.type]
    elif args.type in SIGNATURES.values():
        img_sig = args.type
    else:
        print(f'Invalid image type, supported are:', file=sys.stderr)
        for k in sorted(SIGNATURES):
            print(f'  {k} ({SIGNATURES[k]})', file=sys.stderr)
        return 1

    burn_addr: int = args.burn_addr
    if burn_addr & 3:
        print('Burn offset must be 4-byte aligned', file=sys.stderr)
        return 1

    load_addr: int = args.load_addr
    if load_addr & 3:
        print('Load address must be 4-byte aligned', file=sys.stderr)
        return 1

    input_file: BinaryIO | None = args.input
    img_len = 0
    if input_file is not None:
        input_file.seek(0, os.SEEK_END)
        img_len = input_file.tell()
        input_file.seek(0)

    if args.len is not None:
        if args.len > img_len:
            print(
                f'Length longer than input, {args.len} > {img_len}',
                file=sys.stderr)
            return 1
        img_len = args.len

    img = input_file.read() if input_file is not None else b''

    with open(args.output, 'wb') as f:
        f.write(img_sig.encode())
        f.write(load_addr.to_bytes(4, 'big'))
        f.write(burn_addr.to_bytes(4, 'big'))
        f.write(img_len.to_bytes(4, 'big'))
        f.write(img)

    return 0


if __name__ == '__main__':
    exit(main())
