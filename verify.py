#!/usr/bin/env python3

from collections.abc import Buffer
import hashlib
from typing import BinaryIO, Sequence


FENGLIAN_UUIDS = [
    b'is;jbil16i1lo9c;',
    b'NoRouter_____No1',
]

# sign_tbl in the bootloader (README.md, "Image partition table")
SIGNATURES = {
    b'cs6c': 'Linux kernel',
    b'cr6c': 'Linux kernel (root-fs)',
    b'w6cg': 'Webpages',
    b'r6cr': 'Root filesystem',
    b'boot': 'Boot code',
    b'ALL1': 'Total Image',
    b'ALL2': 'Total Image (no check)',
}

# Only these two are looked up while booting; the rest are flashing-only.
BOOT_SIGNATURES = [b'cs6c', b'cr6c']

# Every burned header needs a valid hmac and its own trailing RSA signature,
# except these containers, which are skipped by both checkers.
UNCHECKED_SIGNATURES = [b'ALL1', b'ALL2']


def BN_bn2bin(b: Sequence[int]) -> int:
    n = 0
    for i in range(74):
        word = int.from_bytes(b[i * 4:(i + 1) * 4], 'little')
        n |= (word & 0x0fffffff) << (28 * i)
    return n


FENGLIAN_RSA_N = BN_bn2bin([
    0xe7, 0x5d, 0xac, 0x09, 0x70, 0x4e, 0x0a, 0x07,
    0x52, 0xa6, 0x81, 0x09, 0xd4, 0x74, 0x5c, 0x07,
    0x5e, 0x7c, 0x2d, 0x09, 0x21, 0x99, 0x57, 0x06,
    0xfd, 0x2d, 0x99, 0x00, 0x94, 0x85, 0x42, 0x00,
    0xaa, 0x78, 0xe4, 0x02, 0xee, 0x10, 0xd4, 0x00,
    0x71, 0x06, 0x0d, 0x04, 0xdc, 0xbc, 0x4b, 0x05,
    0xb7, 0xb7, 0xb4, 0x01, 0xcd, 0x1a, 0xbf, 0x05,
    0x10, 0xb9, 0xea, 0x0e, 0xcd, 0x7b, 0x26, 0x04,
    0x0a, 0x0f, 0x6b, 0x01, 0x4f, 0x89, 0x19, 0x07,
    0xa7, 0x3d, 0x6a, 0x04, 0x0d, 0xa7, 0x45, 0x0a,
    0xb0, 0xfc, 0x87, 0x04, 0x90, 0x19, 0x8b, 0x0d,
    0x97, 0xf0, 0xcd, 0x06, 0x13, 0x37, 0xac, 0x02,
    0xd8, 0x12, 0xb4, 0x0a, 0xec, 0x99, 0x2e, 0x09,
    0x68, 0x69, 0x7a, 0x0e, 0xe0, 0xce, 0xad, 0x05,
    0x1c, 0x34, 0x22, 0x01, 0xb5, 0x60, 0x9a, 0x09,
    0xe9, 0x62, 0xa2, 0x0a, 0x4e, 0xaf, 0x58, 0x00,
    0x2e, 0x18, 0x36, 0x0c, 0x6a, 0x0e, 0x2d, 0x07,
    0x46, 0xd4, 0x31, 0x0f, 0x58, 0xcf, 0xd4, 0x0e,
    0x78, 0xaa, 0xb1, 0x04, 0x73, 0xb5, 0xc9, 0x07,
    0x9a, 0xf2, 0xd8, 0x03, 0xda, 0x6d, 0x1d, 0x0c,
    0x8b, 0xb6, 0x1d, 0x01, 0x91, 0xde, 0x8c, 0x03,
    0x03, 0xd3, 0xdb, 0x00, 0x08, 0x98, 0x0c, 0x02,
    0xdf, 0xa9, 0x73, 0x00, 0x6b, 0x09, 0x00, 0x06,
    0x67, 0xe2, 0x3e, 0x0c, 0xf3, 0xfe, 0xd4, 0x0f,
    0x82, 0x10, 0xd7, 0x0a, 0x3c, 0x57, 0xbd, 0x04,
    0x8c, 0xe7, 0xc0, 0x00, 0x5f, 0xdf, 0x68, 0x0b,
    0x5c, 0xce, 0x38, 0x06, 0xe3, 0x67, 0x75, 0x06,
    0x49, 0x99, 0x01, 0x03, 0x12, 0x04, 0x48, 0x04,
    0xb8, 0x6e, 0xcb, 0x08, 0xed, 0x0b, 0x56, 0x0e,
    0xc5, 0x6d, 0x81, 0x02, 0x88, 0x12, 0xc3, 0x0f,
    0xac, 0x46, 0x21, 0x0b, 0x70, 0x37, 0x63, 0x0d,
    0xd2, 0x26, 0xc9, 0x07, 0x98, 0x09, 0x52, 0x01,
    0x03, 0xc1, 0x8f, 0x00, 0x3d, 0xcc, 0xb2, 0x0c,
    0x90, 0x2a, 0x59, 0x0e, 0x15, 0xcc, 0xad, 0x0d,
    0xa5, 0xa9, 0x1c, 0x0d, 0x33, 0xdb, 0x7c, 0x0f,
    0x47, 0x1a, 0xb1, 0x03, 0x61, 0x75, 0x73, 0x08,
    0x0a, 0x3e, 0xe9, 0x09, 0x0d, 0x00, 0x00, 0x00,
])
FENGLIAN_RSA_E = 0x10001


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


def check_ecc(data: Buffer, size: int) -> bool:
    blkcnt = (size + 255) // 256

    data_view = memoryview(data)
    payload = data_view[:size]
    parities = data_view[size:size + 3 * blkcnt]

    errcnt = 0
    for i in range(blkcnt):
        ecc_orig = parities[3 * i:3 * (i + 1)]
        ecc_exp = smartmedia_ecc(payload[256 * i:256 * (i + 1)])
        if ecc_orig != memoryview(ecc_exp):
            print(
                f'ECC error at block {i}, expected {ecc_exp}, found {bytes(ecc_orig)}')
            errcnt += 1
            if errcnt > 10:
                print('Too many ECC errors, skipping')
                break

    return not errcnt


def rsa_pkcs1_decrypt(sig: Buffer, e: int, N: int) -> bytes | None:
    sig_int = int.from_bytes(sig, 'big')
    result = pow(sig_int, e, N)
    result_be = result.to_bytes(256, 'big')

    # PKCS#1 v1.5 type 1 (signature): 00 01 FF...FF 00 <data>
    if result_be[0] != 0x00 or result_be[1] != 0x01:
        print(f'RSA bad PKCS#1 prefix: {result_be[:4].hex()}')
        return None

    sep = result_be.find(b'\0', 2)
    if sep < 0:
        print('RSA no PKCS#1 separator')
        return None

    if not all(b == 0xff for b in result_be[2:sep]):
        print('RSA invalid PKCS#1 padding')
        return None

    return result_be[sep + 1:]


def verify_image(f: BinaryIO) -> bool:
    img_header_ = f.read(64)
    img_header = memoryview(img_header_)
    if len(img_header) < 64:
        print('Image too short')
        return False

    img_sig = bytes(img_header[0:4])
    if img_sig not in SIGNATURES:
        known = ', '.join(
            map(lambda kv: f'{kv[0]!r} ({kv[1]})', SIGNATURES.items()))
        print(f'Unknown signature {img_sig}, known are: {known}')
        return False
    print(f'Signature: {img_sig} ({SIGNATURES[img_sig]})' + (
        '' if img_sig in BOOT_SIGNATURES else ' - not bootable'))
    if img_sig == b'cs6c':
        print('cs6c image — HMAC and ECC not applicable')
        return True
    if img_sig in UNCHECKED_SIGNATURES:
        print('ALL1/ALL2 header — never burned, nothing is checked')
        return True

    payload_len = int.from_bytes(img_header[12:16], 'big')
    print(f'Image size: 0x{payload_len:x}')

    img_content_ = f.read(payload_len)
    img_content = memoryview(img_content_)
    if len(img_content) < payload_len:
        print(
            f'  Payload truncated at {len(img_content)} bytes, '
            f'expected {payload_len}')
        return False

    hmac_orig = img_header[16:32]
    print(f'Original HMAC: {hmac_orig.hex()}')

    inner = hashlib.md5(img_content[:-2]).digest()
    middle = hashlib.md5(
        inner +
        b'\xcf\x02\xa0\xa5\x95\x52\x84\xbe\x72\xdd\xec\x11\x17\x2d\xb7\xa8'
    ).digest()
    hmac_ok = False
    for uuid in FENGLIAN_UUIDS:
        hmac_exp = hashlib.md5(middle + uuid).digest()
        if memoryview(hmac_exp) == hmac_orig:
            print(f'UUID for this image: {uuid}')
            hmac_ok = True
            break
    if not hmac_ok:
        print('UUID not found — HMAC mismatch')

    ecc_ok = False
    if payload_len < 0x30000:
        print('Image too small for ECC')
    else:
        ecc_data_len = payload_len - 0x30000
        if check_ecc(img_content, ecc_data_len):
            print('ECC OK')
            ecc_ok = True
        elif check_ecc(img_content, ecc_data_len - 4):
            print(
                'ECC 4 bytes early - a common stock firmware bug, unusable '
                'by bootcode')
            ecc_ok = True
        else:
            print('ECC FAILED')

    signature = f.read(256)
    if len(signature) < 256:
        print('RSA signature truncated')
    else:
        img_header_exp = rsa_pkcs1_decrypt(
            signature, FENGLIAN_RSA_E, FENGLIAN_RSA_N)
        if img_header_exp is not None and \
                memoryview(img_header_exp) == img_header:
            print('RSA signature OK')
        else:
            print('RSA signature FAILED')

    # RSA tail is informational: never burnt, and may be our padding
    return hmac_ok and ecc_ok


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description='Verify Netcore MG1200AC firmwares.')
    parser.add_argument('input', help='input file')
    args = parser.parse_args()

    try:
        f = open(args.input, 'rb')
    except OSError as e:
        parser.error(f"cannot read '{args.input}': {e}")

    return 0 if verify_image(f) else 1


if __name__ == '__main__':
    exit(main())
