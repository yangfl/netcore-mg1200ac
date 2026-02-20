#!/usr/bin/env python3

import hashlib
import sys


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


with open(sys.argv[1], 'rb') as f:
    content = f.read()
content_view = memoryview(content)

header = content_view[:64]
img_len = int.from_bytes(header[12:16], 'big')
print(f'Image size: 0x{img_len:x}')
if len(content) < img_len + 64:
    print(f'  Read image (0x{len(content) - 64:x}) smaller than expected')
img = content_view[64:64 + img_len - 2]

hmac_orig = header[16:32]
print(f'Original hmac: {hmac_orig.hex()}')

hmacobj_data = hashlib.md5()
hmacobj_data.update(hashlib.md5(img).digest())
hmacobj_data.update(
    b'\xcf\x02\xa0\xa5\x95\x52\x84\xbe\x72\xdd\xec\x11\x17\x2d\xb7\xa8')
hmac_data = hmacobj_data.digest()
for fenglian_uuid in FENGLIAN_UUIDS:
    hmac_exp = hashlib.md5(hmac_data + fenglian_uuid).digest()
    if hmac_exp == hmac_orig:
        print(f'UUID for this image: {fenglian_uuid}')
        break
else:
    print('UUID not found')

if img_len < 0x30000:
    print('Image too small for ECC')
else:
    ecc_data_len = img_len - 0x30000
    ecc_data = img[:ecc_data_len]
    ecc_blk_cnt = (ecc_data_len + 255) // 256
    # some use 64 + ecc_data_len - 4
    ecc_parities = content_view[
        64 + ecc_data_len:64 + ecc_data_len + 3 * ecc_blk_cnt]

    ecc_err_cnt = 0
    for i in range(ecc_blk_cnt):
        ecc_orig = ecc_parities[3 * i:3 * (i + 1)]
        ecc_exp = smartmedia_ecc(ecc_data[256 * i:256 * (i + 1)])
        if ecc_orig != ecc_exp:
            print(
                f'ECC error at block {i}, expected {ecc_exp}, found {bytes(ecc_orig)}')
            ecc_err_cnt += 1
            if ecc_err_cnt > 10:
                print('Too many ECC errors, skipping')
                break
    if not ecc_err_cnt:
        print('ECC OK')
