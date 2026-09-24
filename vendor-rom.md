# Netcore MG1200AC vendor ROM

Sample: `Netcore-MG1200AC-V1.0.7.54189.bin` (from `netcore-mg1200ac-rom`).

The "expected" layout is `header || kernel || rootfs || rootfs offset || ecc || signature` (as seen in SH variant). However, Netcore made a mistake: `header || kernel || rootfs || ecc || rootfs offset || signature`, making ECC 4-byte earlier than bootcode expects - still bootable, but bootcode won't be able to fix it if any bits are corrupted.

UART access is disabled (`turn off boot console early0`). The vendor kernel cmdline is `console=/dev/null root=/dev/mtdblock5`. The `::askfirst:/bin/sh` in `/etc/inittab` has an empty id field, so busybox init attaches it to `/dev/console` = `/dev/null`, and so is every `console_printf` user (`/dev/console`). You might not be able to get any hints for an incorrect image from the console if the error happens after UART is disabled.

## Enable serial shell

One line in `/etc/inittab` — replace the stock `::askfirst:/bin/sh` with:

```
ttyS0::respawn:/bin/sh
```

plus a three-line prelude in `/etc/rcS`, right after `mount -t devpts` (line 6):

```sh
# serial console shell via inittab (ttyS0::respawn)
/bin/busybox mknod /dev/ttyS0 c 4 64
/bin/busybox stty -F /dev/ttyS0 38400 cs8 -parenb
/bin/busybox echo "console enabled" > /dev/ttyS0
```

Why each piece is needed:

1. The id field `ttyS0` is the whole trick: busybox init opens `/dev/ttyS0` as the shell's stdio/controlling tty instead of the `/dev/null` console. The stock `::askfirst` line was never broken as a command — it was just talking into `/dev/null`.
2. The 8250 driver leaves ttyS0 at a non-38400 baudrate after probe, and init does not set termios; `stty` must run in rcS (before the respawn entry opens the port) or the console is garbage/silent.
3. `mknod` covers a static `/dev` (with devtmpfs it is a harmless no-op). `respawn` instead of `askfirst` means no Enter-to-activate, and init restarts the shell if it ever exits.
4. Ordering is safe: busybox init runs `::sysinit` to completion before processing the respawn entry, and rcS always terminates (`sh/init.sh` is `/bin/switch -d; sleep 10`), so the shell appears ~15 s into userspace.

## Telnet via replaced busybox

Replace `/bin/busybox` with upstream static build (no FPU). Add to `/etc/inittab`:

```
::respawn:/sbin/telnetd -F -l /bin/sh -p 23
```

telnetd needs pty. In `/etc/rcS`, add

```
mkdir -p /dev/pts
```

**before** `mount -t devpts devpts /dev/pts` (the dir never existed, mount failed silently).

**Vendor `telnetd` is a stub.** The vendor busybox replaces `telnetd_main` (stock binary, `0x42b240`) with `while (1) sleep(-1);` — the code never reaches `socket()/bind()`. On-board `/bin/busybox telnetd -l /bin/sh -p 2323 -F` returns silently, no listener. There is also no firewall to open: no iptables binary or applet exists in the rootfs, and unfiltered ports answer `RST(closed)`.

## Register / memory primitives via iwpriv (local root)

The wifi driver (rtl8192cd/rtl8192f family, `_IOCTL_DEBUG_CMD_` enabled) exposes a full register/memory access suite through private ioctls. All arguments are comma-separated; a bare number without the required comma format fails with `invalid type` and surfaces as `Operation not permitted`. Types: `b`/`w`/`dw` operate on offsets relative to the wifi ioaddr, `_b`/`_w`/`_dw` on absolute addresses (offset 0 based). Output is capped at 128 bytes per call.

| command | format | status | example (measured on V1.0.7 board) |
| --- | --- | --- | --- |
| `read_reg` | `type,offset` | works | `iwpriv wlan0 read_reg dw,0` → `255 195 178 146` (value `0xFFC3B292`; the four decimals are printed most-significant byte first) |
| `write_reg` | `type,offset,val` | works (source) | |
| `read_mem` | `type,addr,len` | works | `iwpriv wlan0 read_mem dw,87000000,10` |
| `write_mem` | `type,addr,len,val` | works | val is repeated `len` times; write/read-back/restore of 0xDEADBEEF at 0x87000000 verified |
| `read_rf` | `path,offset` | works | `iwpriv wlan0 read_rf 0,0` → `0 3 29 185` (0x031DB9) |
| `write_rf` | `path,offset,val` | works (source) | 20-bit RF registers, prints read-back value |
| `read_bb` / `write_bb` | — | **stub** | name is registered and the ioctl dispatches, but the handler is `return 0;` — always empty output |
| `read_eeprom` / `write_eeprom` | — | **stub** | handler `return -1` |
| `reg_dump`, `dump_mib`, `copy_mib` | — | present | large output; avoid over a slow UART |

Notes:

1. `read_mem`/`write_mem` take a raw kernel pointer (`memcpy((char *)start, ...)` in the driver), so they reach DRAM and MMIO alike — this is the strongest primitive (arbitrary kernel memory read/write), gated to local root only.

   Byte order differs between the two readers: `read_reg` prints the dword's bytes most-significant first, while `read_mem` prints them in memory (little-endian, lowest address first) order — e.g. writing `0xDEADBEEF` and reading back gives `239 190 173 222` = `EF BE AD DE`. Pass DRAM addresses as kseg0 (`0x8_______`); a kseg1 MMIO pointer to `read_mem` has been observed to hang the vendor kernel until the hardware watchdog resets the board, so use it for RAM (descriptor rings, buffers) only.
2. `wlan0`/`wlan1` carry the full table; secondary interfaces (e.g. `wlan1-wd`) accept only a subset, and a command not in an interface's table prints `no private ioctls`.
3. The upstream SDK wires these same handlers into the MP daemon (`users/mp-daemon/UDPserver.c`, unauthenticated UDP port 9034, `iwpriv wlan0 read_reg ...` → `system()` → `/tmp/MP.txt` → `flash read`). Netcore did not compile that daemon into any of the three MG1200AC firmwares (1.0.7/1.2.7/SH-1.2.1): no binary, no 9034 listener — so the remote vector behind CVE-2021-35394 is absent here; the primitives are reachable only from a local shell.

## CLI WiFi scanner

```
./wl_cnd [-i ifidx] [-b bandwidth] [-s sideband] [-t]
  -i : ifidx, default is 0
  -b : bandwidth: 80,40,20...
  -s : sideband: 0:lower, 1:upper
  -t : print the verbose scan result to stdout
```

There is no `-h`/`--help` option for `wl_cnd` - pass an invalid option to see the usage message (`wl_cnd -b 15`).
