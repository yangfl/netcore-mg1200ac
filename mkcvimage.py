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

import os


SIGNATURES = {
    'linux': b'csys',
    'linux_root': b'csro',
    'root': b'root',
    'web': b'webp',
    'linux_8198': b'cs6c',
    'linux_root_8198': b'cr6c',
    'root_8198': b'r6cr',
    'web_8198': b'w6cg',
    'cmd': b'cmd ',
    'boot': b'boot',
    'iram': b'iram',
    'all': b'ALL1',
    'all_unchecked': b'ALL2',
}


def auto_int(x: str | bytes | bytearray) -> int:
    return int(x, 0)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description='Build Realtek firmware. NOT for Netcore hardened bootcode.')

    parser.add_argument(
        '-T', '--type', type=str, default='fw',
        help='image type, pass -h to see the list (default: %(default)#s)')
    parser.add_argument(
        '-a', '--load-addr', type=auto_int, default=0x80a00000,
        help='image load address (default: %(default)#x)')
    parser.add_argument(
        '-b', '--burn-addr', type=auto_int, default=0x30000,
        help='flash burn offset (default: %(default)#x)')
    parser.add_argument(
        '-l', '--len', type=auto_int, default=None,
        help='image length (default: input file length)')
    parser.add_argument(
        '-d', '--input',
        help='input file')
    parser.add_argument('output', type=str, help='output file')

    args = parser.parse_args()

    img_sig: bytes
    if args.type in SIGNATURES:
        img_sig = SIGNATURES[args.type]
    elif args.type.encode() in SIGNATURES.values():
        img_sig = args.type.encode()
    else:
        parts = ['Invalid image type, supported are:']
        for k in sorted(SIGNATURES):
            parts.append(f'  {k} ({SIGNATURES[k].decode()})')
        parser.error('\n'.join(parts))

    load_addr: int = args.load_addr
    if load_addr & 3:
        parser.error('Load address must be 4-byte aligned')

    burn_addr: int = args.burn_addr
    if burn_addr & 3:
        parser.error('Burn offset must be 4-byte aligned')

    if not args.input:
        input_file = None
    else:
        try:
            input_file = open(args.input, 'rb')
        except OSError as e:
            parser.error(f"cannot read '{args.input}': {e}")

    payload_len = 0
    if input_file is not None:
        input_file.seek(0, os.SEEK_END)
        payload_len = input_file.tell()
        input_file.seek(0)

    if args.len is not None:
        if args.len > payload_len:
            parser.error(f'Length longer than input, {args.len} > {payload_len}')
        payload_len = args.len

    payload = input_file.read() if input_file is not None else b''

    with open(args.output, 'wb') as f:
        f.write(img_sig)
        f.write(load_addr.to_bytes(4, 'big'))
        f.write(burn_addr.to_bytes(4, 'big'))
        f.write(payload_len.to_bytes(4, 'big'))
        f.write(payload)

    return 0


if __name__ == '__main__':
    exit(main())
