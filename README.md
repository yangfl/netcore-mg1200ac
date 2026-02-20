# Netcore MG1200AC boot code writeup

Netcore MG1200AC bootloader employs HMAC-MD5 during booting, and RSA during flashing. This article describes the verification process and possible workarounds.

## RTL819x boot code overview

> UART baud rate: 38400

The original RTL819x boot code looks for `IMG_HEADER_T` in three specific locations (`0x10000`, `0x20000`, `0x30000`) for system booting.

> `start_kernel() -> check_image() -> check_image_header()`

Press 'ESC' in the console (or the RESET button, depending on the config) to escape the booting process. The bootloader starts TFTP and HTTP server at `192.168.1.6`. It would burn the firmware to the flash once it receives the firmware from TFTP client or HTTP web page.

> `tftp 192.168.1.6 -m binary -v -c put <fw.bin>`

However, not only Netcore MG1200AC changes the image format, it also employs cryptographic verification over the image payload. You would likely encounter `the uuid is error,reboot now!` if you upload a random image.

## Netcore MG1200AC firmware image format

`IMG_HEADER_T` was extended from 16 bytes to 64 bytes.

```c
// modified from boot/init/rtk.h

#define SIG_LEN 4

typedef struct __attribute__((__packed__)) _img_header_ {
  uint8_t signature[SIG_LEN];
  // load address for the remaining data (not including the header) during booting
  uint32_t startAddr;
  // target flash address, whether the header is included is determined by `sign_tbl::skip`
  uint32_t burnAddr;
  uint32_t len;

  // below are extra fields added by Netcore MG1200AC

  uint8_t hmac[16];
  // image name
  char name[16];
  // device version, unset or greater than bootloader version
  char version[12];
  uint32_t unknown;
} IMG_HEADER_T;
```

Only `cr6c` (`FW_SIGNATURE_WITH_ROOT`) and `cs6c` (`FW_SIGNATURE`) are recognized by Netcore MG1200AC.

For `cr6c`, `check_image_header()` will load data of size `len` from flash to `startAddr` and verify it against `hmac`. If failed, it will attempt to fix it with ECC (see below).

For `cs6c`, `check_image_header()` will _not_ load the data nor verify the `hmac`, but still jump to `startAddr`.

The RESET button is recognized only if:
- `cr6c` is found at one of the three possible locations;
- any non `\xff` data is found in `0xfe0000-0xfe0004` and `0xff0000-0xff0004`, which prevents booting interrupt during factory reset the vendor firmware.

You can make use of memory-mapped region `0x90000000-0x91000000` of the flash contents to boot the system if applicable.

`hmac` is calculated by

```
data = image[sizeof(IMG_HEADER_T) : sizeof(IMG_HEADER_T) + Header.len - 2]
msg = md5(data) || '\xcf\x02\xa0\xa5\x95\x52\x84\xbe\x72\xdd\xec\x11\x17\x2d\xb7\xa8'
hmac = md5(msg) || UUID
```

where `UUID` can be either `is;jbil16i1lo9c;` or `NoRouter_____No1`. Both UUID are valid.

100-byte RSA signature is appended at the end of file, located at `64 + Header.len`. The signature is only verified during flashing (`checkAutoFlashing()`) and not burnt into flash.

### ECC

For `cr6c`, the last `0x30000` bytes of the image contain ECC parities.

Thanks for Netcore, if `cr6c` image `len` is less than `0x30000`, the behavior is undefined.

> `0x1f000` also contains ECC parities for gzipped bootloader in `0x8c00`.

## Possible workarounds

### XMODEM

`xmodem` command can be used to receive any data and load it into memory.

`Usage: xmodem <buf_addr> [jump]`

### Hot patch

`EW` command can be used to hot patch anything, including the bootloader. The main body of bootloader is dynamically extracted and loaded into memory, so no permanent change would be made.

`EW <Address> <Value1> <Value2>...`

Example of disabling RSA verification (binary patch, please check your own version):

```
80002558    jal     dprintf
8000255C    li      $a0, aRsaErrorReboot  # "rsa error ,reboot now!\n"
80002560    jal     autoreboot
80002564    nop
80002568    lui     $a2, 0x8002
8000256C loc_8000256C:
8000256C    jal     dprintf
80002570    addiu   $a0, $a2, (aRsaCheckPassSt - 0x80020000)  # "rsa check pass ,start upgrade!\n"
```

```
<RealTek>DW A0002560
A0002560:       0C000517        00000000        3C068002        0C005D69
<RealTek>EW A0002560 0
```

Use `./mkfenglianimage.py -t root -b <flash offset> -d <input> <output>` to build the image.

### TFTP debug file

Some file names can trigger the debug function of TFTP server (`setTFTP_WRQ()`). If the file name contains `nfjrom` (`TEST_FILENAME`), the payload will be executed immediately instead of burning to flash, which also bypasses the signature check.

## Appendix

### Links
- [[OpenWrt Wiki] Realtek](https://openwrt.org/docs/techref/hardware/soc/soc.realtek)
- [rtl819x-SDK-v3.4.11C-full-package_20170418-2.tar.gz](https://t.me/Realtek_Switch_Hacking/70): for `bootcode_rtl8197f` source code

### Boot log
```
Booting...
init_ram
 00000202 M init ddr ok

DRAM Type: DDR2
        DRAM frequency: 533MHz
        DRAM Size: 128MB
JEDEC id EF4018
found w25q128
lock flash for init...
flash vendor: Winbond
w25q128, size=16MB, erasesize=64KB, max_speed_hz=29000000Hz
auto_mode=0 addr_width=3 erase_opcode=0x000000d8
=>CPU Wake-up interrupt happen! GISR=89000004

---Realtek RTL8197F boot code at 2017.12.01-13:26+0800 v3.4.11B (999MHz)
no sys signature at 00010000!
no sys signature at 00020000!
fw check sum OK with right uuid
Jump to image start=0x80a00000...
decompressing kernel:
Uncompressing Linux... done, booting the kernel.
done decompressing kernel.
start address: 0x804e31f0
Linux version 3.10.90 (root@netcore) (gcc version 4.4.7 (Realtek MSDK-4.4.7 Build 2001) ) #2 Fri Jul 27 11:40:47 CST 2018
bootconsole [early0] enabled
CPU revision is: 00019385 (MIPS 24Kc)
```

License: all my work is under public domain
