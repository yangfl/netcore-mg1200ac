# Netcore MG1200AC boot code writeup

Netcore MG1200AC bootloader employs HMAC-MD5 during booting, and RSA during flashing. This article describes the verification process and possible workarounds.

## RTL819x boot code overview

> UART baud rate: 38400

The original RTL819x boot code looks for `IMG_HEADER_T` in three specific locations (`0x10000`, `0x20000`, `0x30000`) for system booting.

> `start_kernel() -> check_image_header() -> check_system_image() / check_image_uuid() / check_rootfs_image()`

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
  // load address for the remaining data (not including the header) during booting, big-endian
  uint32_t startAddr;
  // target flash address, whether the header is included is determined by `sign_tbl::skip`, big-endian
  uint32_t burnAddr;
  // payload length, big-endian
  uint32_t len;

  // below are extra fields added by Netcore MG1200AC

  uint8_t hmac[16];
  // image name
  char name[16];
  // device version, unset or greater than bootloader version
  char version[12];
  // build number, purely informational and not used by the bootloader, little-endian
  uint32_t build;
} IMG_HEADER_T;
```

At _booting_ time only `cr6c` (`FW_SIGNATURE_WITH_ROOT`) and `cs6c` (`FW_SIGNATURE`) are recognized (`check_system_image()`), but the flashing path accepts more signatures, see [Image partition table](#image-partition-table).

For `cr6c`, the image payload is always read from flash offset `0x30000` (regardless of whether the header was found at `0x10000`, `0x20000`, or `0x30000`), loaded to `startAddr`, and verified against `hmac`. If the HMAC check fails, it will attempt to fix the data with ECC (see below) and re-verify - and if it still fails the device does not reboot into a loop, it enters [Auto Recover Mode](#auto-recover-mode).

> For headers at `0x10000`/`0x20000`, the image data is **not** read directly from the header, but at the fixed offset `0x30000`, this is a left-over from vendor SDK.

For `cs6c`, `check_image_header()` will _not_ load the data nor verify the `hmac`, but still jump to `startAddr`.

`hmac` is calculated by

```
data = image[sizeof(IMG_HEADER_T) : sizeof(IMG_HEADER_T) + Header.len - 2]
inner = md5(data)
middle = md5(inner || '\xcf\x02\xa0\xa5\x95\x52\x84\xbe\x72\xdd\xec\x11\x17\x2d\xb7\xa8')
hmac = md5(middle || UUID)
```

where `UUID` can be either `is;jbil16i1lo9c;` or `NoRouter_____No1`. Both UUID are valid.

256-byte RSA signature is appended at the end of file, located at `64 + Header.len`. The signature is only verified during flashing (`checkAutoFlashing()`) and not burnt into flash. See [RSA public key](#rsa-public-key) for the embedded key.

For `startAddr`, you can make use of memory-mapped region `0x90000000-0x91000000` of the flash contents to boot the system if applicable.

### Image partition table

`sign_tbl` (`0x800263EC`, 7 entries, layout identical to the vendor SDK `SIGN_T`) drives `checkAutoFlashing()`. Only the first two are looked at while booting; the rest are flashing-only partitions:

| signature | comment | `sig_len` | `skip` | `maxSize` | `reboot` | extra per-type check |
| --- | --- | --- | --- | --- | --- | --- |
| `cs6c` | Linux kernel | 4 | 0 | `0x2C0000` | 1 | - |
| `cr6c` | Linux kernel (root-fs) | 4 | 0 | `0x2C0000` | 1 | ECC at boot time |
| `w6cg` | Webpages | 3 | 0 | `0x20000` | 0 | 8-bit byte sum of the payload must be `0` |
| `r6cr` | Root filesystem | 4 | 1 | `0x100000` | 0 | 16-bit sum computed, never compared |
| `boot` | Boot code | 4 | 1 | `0x10000` | 1 | 16-bit sum computed, never compared |
| `ALL1` | Total Image | 4 | 1 | `0x200000` | 1 | 16-bit sum computed, never compared |
| `ALL2` | Total Image (no check) | 4 | 1 | `0x200000` | 1 | none |

Note what the table does _not_ show: the HMAC and RSA checks in `checkAutoFlashing()` run for **every** header that is actually burned (`cs6c`, `cr6c`, `w6cg`, `r6cr`, `boot`), not just for `cr6c` - so a `boot` or `r6cr` partition needs its own valid `hmac` and its own trailing 256-byte RSA signature. Also note `sig_len`: `w6cg` is matched on only 3 bytes, so the fourth byte of that signature is free.

`skip` decides whether the 64-byte header is written to flash as part of the payload. Both `imageFileValid()` (the auto-recover path) and `checkAutoFlashing()` (TFTP/HTTP upload) walk the chain of 64-byte headers in one file, and an **unrecognized signature is not an error** - the walker simply skips `len + 64` bytes and carries on, so a file can smuggle arbitrary blocks between recognized headers.

`ALL1` and `ALL2` are never written to flash at all; they only advance the walk. `ALL2` additionally flips the rest of the file into "no check" mode: `imageFileValid()` then accepts any further header whose signature is `boot` or whose payload starts with `sqsh` without matching it against `sign_tbl`, and `checkAutoFlashing()` skips the `w6cg` byte-sum for later partitions (`skip_check_signature`, set in one iteration and consumed in the next).

`checkAutoFlashing()` also honours the header's `version` field as an anti-rollback gate, but in a very Netcore way: it compares the parsed version against the hard-coded `"1.0.8"` and reboots on a downgrade **only if the detected flash chip is neither `0xEF4018` (Winbond W25Q128) nor `0xC84018` (GigaDevice)**. On the stock flash the check is skipped entirely.

### RSA public key

The modulus is stored at `0x8002656C` in `mbedtls_mpi` format (74 little-endian 32-bit limbs, 28 significant bits each, `limb & 0x0FFFFFFF`). `e = 65537`.

### ECC

For `cr6c`, the last `0x30000` bytes of the image contain ECC (SmartMedia) parities. If `cr6c` image is found but HMAC check fails (`fw check sum error`), it will attempt to fix the data (`fw checksum error,try ecc parity...`) and re-verify. If repair succeeds, the repaired image will be written back to flash.

Some Netcore firmwares use the wrong layout: `header || kernel || rootfs || ecc || rootfs offset || signature`, making ECC 4-byte earlier than bootcode expects - still bootable, but bootcode won't be able to fix them if any bits are corrupted.

Thanks to Netcore, if `cr6c` image `len` is less than `0x30000`, the behavior is undefined.

Note that the image header is _not_ protected by ECC. If `len` is damaged, good luck to you.

Same ECC also applies to bootloader itself. `0x1f000` contains ECC parities for gzipped bootloader at `0x8c00`.

## Recovery paths

### RESET button

The RESET button is sampled by `check_image_header()` on the `cr6c` path **only**, and only once the config windows at `0xFE0000`/`0xFF0000` are no longer blank. The button itself is bit 22 of the memory-mapped GPIO input register `0xB8003528`:

```c
if (ret == 2) {                        /* cr6c found at 0x10000/0x20000/0x30000 */
    if (user_interrupt(0)) { ...; goToDownMode(); }
    if (!reversed_blank() && ((*(uint32_t *)0xB8003528 >> 22) & 1) == 0)
        goToDownMode();
    ...
}
```

`reversed_blank()` only returns true when *both* `0xFE0000-0xFE000F` and `0xFF0000-0xFF000F` are still fully erased, so the button is honoured as soon as either 16-byte window holds a single non-`\xff` byte, and the GPIO bit reads `0` while it is held. See [Recovery config block](#recovery-config-block-0xfe0000) for what lives there.

Holding RESET on a `cs6c` image never works: that path returns before the GPIO is read.

### Auto Recover Mode

If a `cr6c` image still failed HMAC check after the ECC retry, it prints `---goToAutoRecoverMode` and stays in the bootloader to pull a rescue image from the vendor cloud (`goToAutoRecoverMode()`, `0x8001906C`):

1. Load the recovery parameters from flash (`sub_80018F88()`, see [Recovery config block](#recovery-config-block-0xfe0000)). Type `1`..`4` selects PPPoE / static / DHCP-with-config / DHCP-without-config; a broken block falls back to type `4`. Unsupported types end up in `goToDownMode()`.
2. `eth_startup()`, then start `tftpd_entry()`, `dhcps_entry()` and `httpd_entry()`.
3. Resolve `recoverup.ifenglian.com` with the built-in DNS client (`sub_8001403C()`, handler `sub_80014C20()`). Any other name in the answer is rejected: `wrong url %s,need %s!`.
4. `send_tftp_rrq("MG1200AC-SH-AUTORECOVER.bin")` against the resolved address.
5. On completion (`sub_800141F4()`) the received buffer goes through `imageFileValid()` and, if `autoBurn` is on, `checkAutoFlashing()` - so the rescue image still needs a valid HMAC and RSA signature - and then the device reboots. A bad image just restarts the TFTP client.

PPPoE (type `1`) is implemented in `sub_80011D74()` and logs the credentials from the config block (`PPPOE id=%s pwd=%s`).

#### How the device asks for recovery

When none of the three header slots holds a signature, `check_image_header()` walks every 4 KiB up to `0x80000`, and for a `cr6c` header found that way it validates a **rootfs** instead (`check_rootfs_image()`), first at `0x260000`, `0x270000`, `0x2B0000`, then every 4 KiB between `0x100000` and `0x300000`. A candidate is accepted when its magic is `sqsh`/`hsqs` **and** the `inodes` field of the squashfs superblock is not `0xFFFFFF7E` (`-130`):

```c
result = 1;
if (byteswap(superblock.inodes) != 0xFFFFFF7E)
    return 1;                 /* healthy -> boot */
/* otherwise poll ESC for ~0x20000 iterations, then */
return 0;                     /* -> auto recover mode */
```

That is the vendor's own "I need rescue" channel: the installed system writes `-130` into `inodes` and reboots. This is also a _reproducible_ trigger for auto recover mode. Note that on this secondary path the `cr6c` image is neither HMAC-checked nor loaded into RAM - the rootfs superblock alone decides between booting and recovering.

#### Recovery config block (0xFE0000)

`sub_80018F88()` reads the provisioning block:

| flash offset | contents |
| --- | --- |
| `0xFE0000` | `uint32_t index` - slot selector, also written to the mirror at `0xFF0000` |
| `0xFE0018 + 0x10 * index` | MD5 (16 bytes) of the following block |
| `0xFE0028 + 0x10 * index` | 568-byte obfuscated parameter block |

The whole block is de-obfuscated in place with a single-byte transform:

```python
plain = bytes(~(b - 18) & 0xFF for b in raw)
```

and `sub_80018E74()` picks between the `0xFE0000` and `0xFF0000` copies by comparing their stored counters, so one valid copy is enough. Offsets inside the 568-byte struct, from `goToAutoRecoverMode()`:

| offset | field |
| --- | --- |
| `0x08` | connection type (`1` PPPoE, `2` static, `3` DHCP with config, `4` DHCP without config) |
| `0x14` | MAC address (6 bytes) |
| `0x1A` | user name (C string), reused as the PPPoE user name |
| `0x9A` | password (C string), reused as the PPPoE password |
| `0x21C` | IP address (static type) |
| `0x220` | gateway (static type) |
| `0x230` | DNS server 1 |
| `0x234` | DNS server 2 |

Writing anything non-`\xff` into those two 16-byte windows is also what makes `reversed_blank()` return false - i.e. a device that has been through the vendor provisioning is exactly the device that *does* honour the RESET button, while a board with both windows still erased ignores it and can only be interrupted with ESC on the UART.

### HTTP emergency page

The download mode HTTP server (`httpd_entry()`) is a single unauthenticated page:

```html
<title>System Repair</title> ... <b>Emergency Web Server</b>
<form enctype=multipart/form-data method=post><input type=file name=userfile>
```

`httpuploadfile()` parses `Content-Length` and the `multipart/form-data` boundary itself and appends file bytes to `httpd_mem_len - 0x5F600000`, i.e. `0xA0A00000 + received_so_far` (the uncached alias of `0x80A00000`, the usual kernel load address) with **no upper bound check** - the copy just keeps running past whatever RAM follows.

Once the announced length is reached it answers with an 879-byte "Upgrade Successfully" page whose JavaScript counts down 120 seconds and then redirects the browser to `http://leike.cc`, sets `readyToUpgrade`, calls `writeImagetoflash((char *)0xA0A00000, httpd_mem_len)` → `checkAutoFlashing()`, and reboots.

### Upgrade counters

The last 64 KiB sector of flash doubles as a little key-value store for the bootloader:

| flash offset | written by | meaning |
| --- | --- | --- |
| `0xAFFFF4` | `sub_80014274()`, from the TFTP client path | bit mask of pending TFTP downloads; each burn clears its lowest set bit |
| `0xAFFFF8` | `sub_8001B6C8()` (`update_http_flag...`) | same idea for HTTP uploads, scanning from bit 1 |
| `0xFE0000` / `0xFF0000` | recovery config copies | slot selector, mirrored for wear |

`0xAFFFF4` is the one `mkfenglianimage.py --alt-uuid` warns about: anything living in that word is consumed as a counter, so an image whose ECC parity area overlaps it will be rewritten by the bootloader.

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

Use `./mkfenglianimage.py -T root -b <flash offset> -d <input> <output>` to build the image.

### TFTP debug file

File names can trigger the debug function of the TFTP server (`setTFTP_WRQ()`, inherited unchanged from the vendor SDK):

- a file name **containing** `nfjrom` (`TEST_FILENAME`, matched with `strstr()`) sets `jump_to_test`;
- a file name **exactly** `boot.img` (`BOOT_FILENAME`) does the same and additionally pins the load address to `0x80000000`.

When the last (short) block arrives, `prepareACK()` jumps to `image_address` - no HMAC, no RSA, nothing.

`image_address` defaults to `0xA0A00000` (uncached alias of the `0x80A00000` kernel load address), so the shortest no-serial path on a shipped board is: hold RESET while powering on, then

```
tftp 192.168.1.6 -m binary -c put whatever-nfjrom.bin
```

and the payload is written to `0xA0A00000` and entered at its cached alias `0x80A00000`.

`LOADADDR` (`CmdLoad()`) sets both `image_address` and `httpd_mem`, so `LOADADDR <addr>` followed by a TFTP upload of any `*nfjrom*` file gives an arbitrary load-and-jump primitive with the same freedom as `xmodem <addr> [jump]`.

## Appendix

### Boot console command list

`MainCmdTable` (`0x80028AA0`) in this build, i.e. everything available at the `<RealTek>` prompt after escaping boot (all addresses/lengths are hex, memory access goes through the uncached alias):

| command | usage | notes |
| --- | --- | --- |
| `?` / `HELP` | print this help | |
| `DB` | `DB <Address> <Len>` | dump bytes |
| `DW` | `DW <Address> <Len>` | dump words |
| `EB` | `EB <Address> <Value1> <Value2>...` | write bytes |
| `EW` | `EW <Address> <Value1> <Value2>...` | write words |
| `E8` | `E8 <Address> <Value>` | |
| `CMP` | `CMP <dst><src><length>` | |
| `MEMCPY` | `MEMCPY <dst><src><length>` | |
| `IPCONFIG` | `IPCONFIG <TargetAddress>` | set the TFTP/HTTP peer |
| `AUTOBURN` | `AUTOBURN 0/1` | gate on `checkAutoFlashing()` |
| `LOADADDR` | `LOADADDR <Load Address>` | TFTP upload/jump target, also `httpd_mem` |
| `J` | `J <TargetAddress>` | jump |
| `FLI` | `FLI` | flash init |
| `FLR` | `FLR <dst><src><length>` | flash read |
| `FLW` | `FLW <dst_ROM_offset><src_RAM_addr><length> <SPI cnt#>` | flash write |
| `ERASESECTOR` | `ERASESECTOR <addr>` | |
| `ERASECHIP` | `ERASECHIP` | |
| `MDIOR` / `MDIOW` | `MDIOR phyid reg` | MII access |
| `PHYR` / `PHYW` | `PHYR <PHYID><reg>` | |
| `PHYPR` / `PHYPW` | `PHYPR <PHYID><page><reg>` | paged PHY access |
| `COUNTER` | `COUNTER` | dump switch ASIC counters |
| `XMOD` | `XMOD <addr> [jump]` | see [XMODEM](#xmodem) |
| `TI` | `TI` | timer init |
| `ETH` | `ETH` | start Ethernet |
| `CPUCLK` | `CPUCLK 999 999` | clock switch, `999` iterates all frequencies |
| `CP0` | `CP0` | dump/modify COP0 registers |
| `T` | `T <len> <loop>` | vendor test command |

The debug commands (`DB`/`DW`/`EB`/`EW`/`CMP`/`IPCONFIG`/`MEMCPY`/`AUTOBURN`) are behind `CONFIG_BOOT_DEBUG_ENABLE` in the SDK; Netcore shipped the whole set enabled.

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
