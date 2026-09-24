#!/usr/bin/env python3

"""
Used by Netcore MG1200AC (recoverup.ifenglian.com), which is derived from
RTL819x boot code `IMG_HEADER_T`.
"""

import argparse
from collections.abc import Buffer
import hashlib
import os
import sys
from typing import Iterable, Literal, cast
import warnings


SIGNATURES = {
    'linux': b'cs6c',
    'linux_root': b'cr6c',
    'root': b'r6cr',
}

FENGLIAN_UUIDS = [
    b'is;jbil16i1lo9c;',
    b'NoRouter_____No1',
]


def smartmedia_hamming_code(i: int) -> int:
    c = (i.bit_count() & 1) << 6
    for j in range(8):
        if i & (1 << j):
            for k in range(3):
                c ^= 1 << (2 * k + (j & (1 << k) != 0))
    return c


SMARTMEDIA_HAMMINGS = [smartmedia_hamming_code(i) for i in range(256)]


def interleave_uint8(x: int) -> int:
    x = (x | (x << 4)) & 0x0f0f
    x = (x | (x << 2)) & 0x3333
    x = (x | (x << 1)) & 0x5555
    return x


def smartmedia_ecc(data: Buffer) -> bytes:
    view = memoryview(data)
    if len(view) > 256:
        raise ValueError

    a = 0
    b = 0
    for i in range(len(view)):
        c = SMARTMEDIA_HAMMINGS[view[i]]
        if c & 0x40:
            a ^= i
        b ^= c

    a1 = interleave_uint8(a)
    a1 = (a1 << 1) | ((~a1 & 0x5555) if b & 0x40 else a1)
    return a1.to_bytes(2, 'big') + (((b & 0x3f) << 2) | 3).to_bytes()


def smartmedia_eccs(data: Buffer) -> bytes:
    view = memoryview(data)
    parts: list[bytes] = []
    for i in range(0, len(view), 256):
        parts.append(smartmedia_ecc(view[i:i + 256]))
    return b''.join(parts)


def fenglian_hmac(md5sum: Buffer, uuid: Buffer = FENGLIAN_UUIDS[0]) -> bytes:
    hmacobj_data = hashlib.md5()
    hmacobj_data.update(md5sum)
    hmacobj_data.update(
        b'\xcf\x02\xa0\xa5\x95\x52\x84\xbe\x72\xdd\xec\x11\x17\x2d\xb7\xa8')

    hmacobj_uuid = hashlib.md5()
    hmacobj_uuid.update(hmacobj_data.digest())
    hmacobj_uuid.update(uuid)
    return hmacobj_uuid.digest()


def fenglian_header(
        *, sig: Buffer = SIGNATURES['linux_root'],
        load_addr: int = 0x80a00000, burn_addr: int = 0x30000,
        payload_len: int, hmac: Buffer,
        name: Buffer = b'', version: Buffer = b'', build: int = 0) -> bytes:
    name_ = memoryview(name)
    version_ = memoryview(version)
    if len(name_) > 16:
        raise ValueError(f'image name too long, {len(name_)} > 16')
    if len(version_) > 12:
        raise ValueError(f'device version too long, {len(version_)} > 12')
    if build < 0 or build > 0xffffffff:
        raise ValueError('invalid build number')
    if payload_len < 2:
        raise ValueError('payload length must be at least 2 bytes')
    if sig == b'cr6c' and payload_len < 0x30000:
        warnings.warn(
            'bootcode will go mad when bit flips if image too short',
            category=UserWarning)
    if load_addr & 3:
        warnings.warn('unaligned load address', category=UserWarning)
    if burn_addr & 3:
        warnings.warn('unaligned burn offset', category=UserWarning)

    parts: list[Buffer] = [
        sig, load_addr.to_bytes(4, 'big'), burn_addr.to_bytes(4, 'big'),
        payload_len.to_bytes(4, 'big'), hmac]
    parts.append(name)
    if len(name_) < 16:
        parts.append(b'\0' * (16 - len(name_)))
    parts.append(version)
    if len(version_) < 12:
        parts.append(b'\0' * (12 - len(version_)))
    parts.append(build.to_bytes(4, 'little'))

    return b''.join(parts)


def fenglian_image(
        payload: Buffer, *,
        sig: Buffer = SIGNATURES['linux_root'],
        load_addr: int = 0x80a00000, burn_addr: int = 0x30000,
        payload_len: int | None = None, uuid: Buffer = FENGLIAN_UUIDS[0],
        name: Buffer = b'', version: Buffer = b'', build: int = 0,
        pad_rsa_sig: bool = False) -> bytes:
    """Wrap a final image body into the fenglian `IMG_HEADER_T` container.

    `payload` is everything after the 64-byte header, already in final form. No
    ECC streams are added.

    `payload_len` can be shorter or longer than the actual size of `payload`. If
    shorter, the rest of the image will be filled with `0xff`. If longer, extra
    bytes will be preserved.

    `pad_rsa_sig` will fill the RSA signature with zero to 256 bytes. It is not
    burnable with unpatched bootcode. With patched bootcode, you still don't
    need it - bootcode will overread the buffer and use that garbage to verify
    the (disabled) signature.
    """
    if payload_len is None:
        padded = memoryview(payload)
        payload_len = len(padded)
    else:
        padded = bytes(payload).ljust(payload_len, b'\xff')

    parts: list[Buffer] = [fenglian_header(
        sig=sig, load_addr=load_addr, burn_addr=burn_addr,
        payload_len=payload_len,
        hmac=fenglian_hmac(hashlib.md5(
            memoryview(padded)[:-2]).digest(), uuid),
        name=name, version=version, build=build), padded]
    if pad_rsa_sig:
        parts.append(b'\0' * 256)

    return b''.join(parts)


def ins2bin(
        l: Iterable[int],
        byteorder: Literal['little', 'big'] = 'little') -> bytes:
    return b''.join(map(lambda ins: ins.to_bytes(4, byteorder), l))


def auto_int(x: str | bytes | bytearray) -> int:
    return int(x, 0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Build Netcore MG1200AC firmwares.')

    parser.add_argument(
        '-T', '--type', type=str, default='linux_root',
        help='image type, pass -h to see the list (default: %(default)#s)')
    parser.add_argument(
        '-a', '--load-addr', type=auto_int, default=0x80a00000,
        help='image load address (default: %(default)#x)')
    parser.add_argument(
        '-b', '--burn-addr', type=auto_int, default=0x30000,
        help='flash burn offset (default: %(default)#x)')
    parser.add_argument(
        '-l', '--len', type=auto_int, default=None,
        help='override payload length, padding if input is shorter, perserve '
        'if longer (default: input file length)')
    parser.add_argument(
        '-n', '--name', type=str, default='',
        help='image name, up to 16 bytes (default: empty)')
    parser.add_argument(
        '-v', '--version', type=str, default='',
        help='device version, up to 12 bytes (default: empty)')
    parser.add_argument(
        '-B', '--build', type=int, default=0,
        help='build number (default: %(default)d)')
    parser.add_argument(
        '--alt-uuid', action='store_true',
        help='use alternate UUID (warning: 0xaffffc+4 will be used as ECC '
        'counter)')
    parser.add_argument(
        '--ecc', type=auto_int, nargs='?', default=0, const=1,
        help='ECC type (0: no ECC, 1: append ECC, 2: prepend stub and its ECC, '
        'make header checksum inrelevant to the payload')
    parser.add_argument(
        '--pad-sig', action='store_true',
        help='append placeholder RSA signature (not burnable through unpatched '
        'bootcode, fails the RSA check; still burnable _without_ it for '
        'patched bootcode')
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

    name_info: bytes = args.name.encode()
    if len(name_info) > 16:
        parser.error(f'Image name too long, {len(name_info)} > 16')

    version_info: bytes = args.version.encode()
    if len(version_info) > 12:
        parser.error(f'Device version too long, {len(version_info)} > 12')

    ecc_type: int = args.ecc
    if ecc_type < 0 or ecc_type > 2:
        parser.error(f'Unknown ECC type {ecc_type}')
    if ecc_type and img_sig != b'cr6c':
        print('Warning: ECC only meant for linux_root images', file=sys.stderr)

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
        payload_len = args.len
    if payload_len < 2:
        payload_len = 2

    payload = input_file.read() if input_file is not None else b''
    payload_view = memoryview(payload)

    if ecc_type == 0:
        img_content = payload_view
    elif ecc_type == 1:
        img_content = bytearray(payload_view)

        if payload_len != len(payload_view):
            parser.error('Overriding payload length for ECC type 1 not allowed')
        if payload_len > 0x10000 * 256:
            parser.error('Image too long for ECC')

        img_content += smartmedia_eccs(payload_view[:payload_len])
        payload_len += 0x30000
    elif ecc_type == 2:
        img_content = bytearray(ins2bin([
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
        payload_len = len(img_content) + 0x30000

        img_content += smartmedia_ecc(img_content)
        # payload instructions must be aligned
        if len(img_content) & 3:
            img_content += b'\0' * (4 - (len(img_content) & 3))
        if len(img_content) != 0x6c - 0x40:
            parser.error(f'Invalid stub length {len(img_content)}')

        # "overlapped" ECC and payload
        img_content += payload_view
    else:
        parser.error(f'Unknown ECC type {ecc_type}')

    uuid = FENGLIAN_UUIDS[cast(int, args.alt_uuid)]
    with open(args.output, 'wb') as f:
        f.write(fenglian_image(
            img_content, sig=img_sig, load_addr=load_addr, burn_addr=burn_addr,
            payload_len=payload_len, uuid=uuid, name=name_info,
            version=version_info, build=args.build, pad_rsa_sig=args.pad_sig))

    return 0


if __name__ == '__main__':
    exit(main())
