#!/usr/bin/env python3

"""
Used by Netcore MG1200AC (recoverup.ifenglian.com), which is derived from
RTL819x boot code `IMG_HEADER_T`.
"""

import argparse
import hashlib
import os
import sys
from typing import TYPE_CHECKING, BinaryIO, Iterable, Literal

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer


SIGNATURES = {
    'linux': 'cs6c',
    'linux_root': 'cr6c',
    'root': 'r6cr',
}

FENGLIAN_UUIDS = [
    b'is;jbil16i1lo9c;',
    b'NoRouter_____No1',
]


def smartmedia_hamming_code(i: int):
    c = (i.bit_count() & 1) << 6
    for j in range(8):
        if i & (1 << j):
            for k in range(3):
                c ^= 1 << (2 * k + (j & (1 << k) != 0))
    return c


SMARTMEDIA_HAMMINGS = [smartmedia_hamming_code(i) for i in range(256)]


def interleave_uint8(x: int):
    x = (x | (x << 4)) & 0x0f0f
    x = (x | (x << 2)) & 0x3333
    x = (x | (x << 1)) & 0x5555
    return x


def smartmedia_ecc(data: bytes | bytearray | memoryview):
    if len(data) > 256:
        raise ValueError

    a = 0
    b = 0
    for i in range(len(data)):
        c = SMARTMEDIA_HAMMINGS[data[i]]
        if c & 0x40:
            a ^= i
        b ^= c

    a1 = interleave_uint8(a)
    a1 = (a1 << 1) | ((~a1 & 0x5555) if b & 0x40 else a1)
    return a1.to_bytes(2, 'big') + (((b & 0x3f) << 2) | 3).to_bytes()


def ins2bin(l: Iterable[int], byteorder: Literal['little', 'big'] = 'little'):
    return b''.join(map(lambda ins: ins.to_bytes(4, byteorder), l))


def fenglian_hmac(
        data: 'ReadableBuffer', fenglian_uuid: bytes = FENGLIAN_UUIDS[0]):
    hmacobj_data = hashlib.md5()
    hmacobj_data.update(hashlib.md5(data).digest())
    hmacobj_data.update(
        b'\xcf\x02\xa0\xa5\x95\x52\x84\xbe\x72\xdd\xec\x11\x17\x2d\xb7\xa8')

    hmacobj_uuid = hashlib.md5()
    hmacobj_uuid.update(hmacobj_data.digest())
    hmacobj_uuid.update(fenglian_uuid)
    return hmacobj_uuid.digest()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-T', '--type', type=str, default='linux_root',
        help='image type, pass -h to see the list (default: linux_root)')
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
        '-n', '--name', type=str, default='',
        help='image name, up to 16 bytes (default: empty)')
    parser.add_argument(
        '-v', '--version', type=str, default='',
        help='device version, up to 12 bytes (default: empty)')
    parser.add_argument(
        '--alt-uuid', action='store_true',
        help='use alternate UUID (warning: 0xaffffc+4 will be used as ECC counter)')
    parser.add_argument(
        '--ecc', type=int, nargs='?', default=0, const=1,
        help='ECC type (0: no ECC, 1: append ECC, 2: prepend stub and ECC)')
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

    name_info: bytes = args.name.encode()
    if len(name_info) > 16:
        print(f'Image name too long, {len(name_info)} > 16', file=sys.stderr)
        return 1

    version_info: bytes = args.version.encode()
    if len(version_info) > 12:
        print(
            f'Device version too long, {len(version_info)} > 12',
            file=sys.stderr)
        return 1

    ecc_type: int = args.ecc
    if ecc_type < 0 or ecc_type > 2:
        print('Invalid ECC type', file=sys.stderr)
        return 1
    if ecc_type and img_sig != 'cr6c':
        print('Warning: ECC only meant for linux_root images', file=sys.stderr)

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
    if img_len < 2:
        img_len = 2

    img_orig = input_file.read() if input_file is not None else b''
    img_orig_view = memoryview(img_orig)

    img = bytearray()
    if ecc_type == 2:
        img = bytearray(ins2bin([
            0x03e04021,  # 40      move    $t0, $ra
            0x04110001,  # 44      bal     4c
            0x3c099000,  # 48      lui     $t1, 0x9000
            0x3529006c,  # 4c      ori     $t1, 0x6c
            0x8feaffbc,  # 50      lw      $t2, -0x44($ra)
            0x7c0a50a0,  # 54      wsbh    $t2
            0x002a5402,  # 58      rotr    $t2, 0x10
            0x01495021,  # 5c      addu    $t2, $t1
            0x01400008,  # 60      jr      $t2
            0x0100f821,  # 64      move    $ra, $t0
        ]))
        img_len = len(img) + 0x30000

        img += smartmedia_ecc(img)
        if len(img) & 3:
            img += b'\0' * (4 - (len(img) & 3))
        if len(img) != 0x6c - 0x40:
            print(f'Invalid stub length {len(img)}', file=sys.stderr)
            return 1

    img += img_orig

    if ecc_type == 1:
        if img_len != len(img):
            print('ECC required but image length mismatch', file=sys.stderr)
            return 1

        ecc_blk_cnt = (img_len + 255) // 256
        if ecc_blk_cnt > 0x10000:
            print('Image too long for ECC', file=sys.stderr)
            return 1

        for i in range(ecc_blk_cnt):
            img += smartmedia_ecc(img_orig_view[256 * i:256 * (i + 1)])
        img_len += 0x30000

    if len(img) < img_len:
        img = img.ljust(img_len, b'\xff')
    img_hmac = fenglian_hmac(
        memoryview(img)[:img_len - 2],
        FENGLIAN_UUIDS[args.alt_uuid])  # type: ignore

    if img_sig == 'cr6c' and img_len < 0x30000:
        print(
            'Warning: bootloader will go mad when bit flips if image too short',
            file=sys.stderr)

    with open(args.output, 'wb') as f:
        f.write(img_sig.encode())
        f.write(load_addr.to_bytes(4, 'big'))
        f.write(burn_addr.to_bytes(4, 'big'))
        f.write(img_len.to_bytes(4, 'big'))
        f.write(img_hmac)
        f.write(name_info.ljust(16, b'\0'))
        f.write(version_info.ljust(12, b'\0'))
        f.write(b'\0\0\0\0')
        f.write(img)

    return 0


if __name__ == '__main__':
    exit(main())
