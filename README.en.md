# a6600 Safe Notes — ASTRA UI Port Research Log

> A research log for porting the **Sony ZV-1M2 (5th-gen, ASTRA touch UI)** UI layer onto the
> **ILCE-6600 (a6600, 4th-gen)**: plans, methods, experiment design, and summaries of static
> and runtime evidence — plus a few of our own configuration files.
>
> **This repository contains no Sony firmware, no firmware-extracted binaries, no Sony
> libraries, no decryption keys, and no runtime logs.**

---

## ⚠️ Read first: safety and legal boundary

This is a reading/methodology archive. It is **not** a flashing package and must not be used to flash a camera.

| Item | Position of this repository |
|---|---|
| Firmware images / extracted trees / `.so` / `.ko` / `.dat` | **Not included at all.** Obtain any material you need from hardware you own and official updaters. |
| Firmware decryption keys | **Not included.** Scripts contain `REDACTED_KEY_*` placeholders — see [docs/SANITIZATION.md](docs/SANITIZATION.md). |
| Camera writes / flashing | Not performed, and no procedure is provided. All experiments were offline (QEMU) or read-only. |
| Flashable firmware | **Does not exist.** The modified image's partition CRC manifest was never regenerated, so it is not flashable. |
| Intended use | Interoperability research and method documentation. Do not use it to circumvent technical protection measures or for commercial redistribution. |

> Sony, ILCE and ZV-1M2 are trademarks of Sony Corporation. This project is unaffiliated with,
> and not endorsed by, Sony. Rights holders may open an issue and we will act promptly.

---

## What this repository is

**In one sentence:** the stock a6600 firmware boots all the way to the stock menu under QEMU; the ASTRA UI port is blocked on one concrete problem — the 5th-gen draw submission is never triggered.

### Included

- `docs/` — **146** research records (numbered by round: plans, hypotheses, results, retracted conclusions)
- `scripts/` — **618** of our own scripts and sources (static analysis, QEMU patches, injection/probes, image tooling)
- `configs/` — a few of **our own** configs: key map, partition layout (derived), QEMU run arguments, kernel command line
- `docs/assets/` — 12 UI screenshots used as evidence

### Not included

- Any Sony firmware, partition image, `firmware.tar`, `BODYDATA.DAT`, or updater executable
- Any library extracted from firmware (`libObj.so`, `appFw.so`, `libIMDB.so`, `input.ko`, …)
- Any decryption key
- Raw runtime logs, or copies of third-party projects
- Early experimental artifacts (`nflasha15_patched.bin`, …)

## Current status

| Item | Status |
|---|---|
| a6600 unpack → repack | ✅ can be **byte-identical** to the original package |
| Stock firmware in QEMU | ✅ reaches the **stock menu** (Settings 4, 4/7); reproduced twice on each of two independent paths |
| Key injection | 🟡 `/proc/udm/input` readable; hardware ADC injection reaches the driver but produces **no key event** |
| 5th-gen UI loading | ✅ libraries load; `appFwBoot::Application_System_Init` returns normally |
| 5th-gen UI drawing | ⛔ `GraphicsEngine::drawFramebuffer` is **never called** (draw kick = 0) |
| Flashable firmware | ⛔ none |

**Confirmed facts**

- **MENU = `0x1AB`, ENTER = `0x1AC`** (early documents had these swapped; corrected in later ones)
- Fonts: `Backup` property `0x810000` points at `/usr/share/app/fontlist.dat`; dropping in three real device fonts works with **zero code changes**
- eMMC stall: fixed by making `emmc.ko`'s tuning function return immediately
- Display: VPH ch53, 640×480 double-buffered; 100+ observed draw kicks
- The UI is a **userland process** (PID 144, 172 threads, `libObj` base `0x057E3000`)

**Retracted conclusions** (kept in the docs as lessons): UI in kernel space; UI never kicks a draw; fonts require `registerFontFaceFile`; `/var/fifo` is the input channel; keys arrive via evdev; sdhci parameters can fix eMMC.

The current blocker, with copy-pasteable question material, is in
[docs/135-第二十二轮基线恢复与fbrm补丁无效.md](docs/135-第二十二轮基线恢复与fbrm补丁无效.md).

## Layout

See the Chinese [README.md](README.md) for the full tree. Top level:

```
docs/      144 research records + menu-92/ + appendix/ + assets/
scripts/   609 scripts & sources, grouped by numeric prefix; tools/, preload/, menu-92/
configs/   keymap/, partitions/, runtime/, probe/
```

## How to read it

Start with [docs/00-工作区总览.md](docs/00-工作区总览.md) (a ten-section authoritative overview), then
[docs/01-方案总览.md](docs/01-方案总览.md) (goal and S0–S5 roadmap), then
[docs/02-已验证事实.md](docs/02-已验证事实.md) and [docs/04-风险与安全边界.md](docs/04-风险与安全边界.md).
Full reading order: [docs/README.md](docs/README.md).

> Documents are numbered by round and **later rounds overturn earlier ones**. Every document notes
> when it was written and how strong the evidence was at that time.

## Reproduction requires your own material

This repository contains methods only. To actually run anything you must supply your own a6600
updater, firmware image, QEMU build with a `sony-a6400` machine, and legally obtained ZV-1M2
libraries. **Do not point these scripts at your camera.** Most were written for the author's
machine; paths have been replaced with placeholders and must be rewritten.

## Evidence grading

Documents mix three kinds of statements, and the project insists on keeping them apart:
**observation** (logs, screenshots, register reads), **inference**, and **unfinished check**.
Failed and retracted results are deliberately retained, never deleted.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Before committing, run:

```bash
python scripts/check_repo_hygiene.py
```

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.
The full text is in [LICENSE](LICENSE).

```
Copyright (C) 2026 a6600 ASTRA research contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```

### What this means

| You may | You must |
|---|---|
| Use, modify and redistribute the code and documents | Keep the copyright notice and license, and state changes |
| Use it commercially | **Release your derivative work under GPL-3.0** |
| Distribute built artifacts | Provide the complete corresponding source |

> **GPL-3.0 is strongly copyleft.** If you incorporate these scripts or documents into your own
> project and distribute it, that whole derivative must also be GPL-3.0. Private reading, study and
> internal use are unaffected.

### Relation to upstream material

- No Sony firmware, Sony binary or decryption key is included, so no Sony work is being relicensed.
- The credited upstream projects (ma1co/Sony-PMCA-RE, fwtool.py, nolan2628/ZVE10-Astra-Public, …)
  are MIT and therefore GPL-3.0-compatible; their code is **not** bundled here.
- `PCIEARIA/A6400-Extra-Menu` is PolyForm Noncommercial 1.0.0, which is **incompatible with
  GPL-3.0**; no code from it is included here either — only acknowledgement and methodological
  inspiration.

## Acknowledgements

### Special thanks: PCIEARIA / A6400-Extra-Menu

[**PCIEARIA/A6400-Extra-Menu**](https://github.com/PCIEARIA/A6400-Extra-Menu) — a research
project on custom touch-overlay menus and LUT management for the Sony A6400 / A6100 — gave this
project **substantial support**, and we gratefully acknowledge it:

- **Ongoing technical support and knowledge sharing** — direct help with a6xxx debugging
  approaches, experiment design, and the paths that lead nowhere, which saved this project a
  great deal of wasted effort;
- **H100 server compute** — static analysis and large batch jobs were run on their H100 server.
  This was a practical prerequisite for completing multiple rounds of symbol scanning, symbol
  closure work, and batch experiments in reasonable time;
- **Camera root access and extraction methodology** — their PMCA service-mode deployment chain and
  the `/etc/a6400-autoexec.so` boot-mount hook were the direct source of our read-only access to a
  real camera and of our verification that root is reachable. Our conclusions about real-device
  partition layout and read-only extraction build on that method.

> `A6400-Extra-Menu` is licensed under **PolyForm Noncommercial 1.0.0**, which differs from this
> repository's licenses. **No code or binary from that project is included here** — we credit it
> and reference its methodology only. If you use their work, follow their license.

### Other public research

Analysis ideas and tooling were additionally informed by public research, credited but **not bundled**:
ma1co/Sony-PMCA-RE, ma1co/fwtool.py, ma1co's QEMU branch, nolan2628/ZVE10-Astra-Public,
anlock6600-related write-ups, and Oein/a5000-cfw.
