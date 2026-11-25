# a6600 × ASTRA — porting the ZV-1M2 (5th-gen) touch menu to the ILCE-6600

> A research log for porting the **Sony ZV-1M2 (5th-gen, ASTRA touch UI)** menu layer onto the
> **ILCE-6600 (a6600, 4th-gen)**, running and validating it in QEMU.
>
> **This repository contains no Sony firmware, no firmware-extracted binaries, no Sony libraries,
> no decryption keys, and no flashable images.**

---

## Read first: boundaries

| Item | Position |
|---|---|
| Firmware images / extracted trees / `.so` / `.ko` / `.uxc` / `.dat` | **Not included.** Obtain any material from hardware you own and official updaters. |
| Firmware decryption keys | **Not included.** Scripts use `REDACTED_KEY_*` placeholders. |
| Flashable images | **Not provided.** Research artefacts contain Sony binaries and must not be redistributed. |
| Camera writes | **Never performed.** Every real-device action was read-only. |
| Intended use | Interoperability research and method documentation. Do not use it to circumvent technical protection measures or for commercial redistribution. |

> Sony, ILCE and ZV-1M2 are trademarks of Sony Corporation. This project is unaffiliated with,
> and not endorsed by, Sony. Rights holders may open an issue and we will act promptly.

---

## Status at a glance

**The ASTRA menu runs in QEMU.**

| Capability | Status |
|---|---|
| Boot → guide page → shooting screen | ✅ |
| MENU toggles the full 52-page menu | ✅ |
| Arrow keys UP / DOWN / LEFT / RIGHT | ✅ |
| Touch navigation through menu levels | ✅ |
| Tap / drag | ✅ |
| Automatic recovery when repaint stops | ✅ (forced-redraw watchdog) |
| Switch to Simplified Chinese | ✅ works, **not persistent** in QEMU |
| Stability in normal use | ✅ 4 minutes idle with zero errors after the fix |
| **After switching language** | ⚠️ triggers a known defect (§ Known defects) |
| **Flashing a real camera** | ⛔ **Not done** — writing `/etc` has no verified recovery path |

---

## What this repository is

Method notes plus reproducible tooling — not a flashing package.

**Included:** `docs/` (research log by round, including retracted conclusions),
`docs/astra-port/` (the six documents from this porting round), `scripts/` (our own tooling),
`scripts/port/` (this round's toolchain: shim builder, image assembler, release packer, auditor,
live demo), `configs/` (our own keymaps, derived partition layout, QEMU parameters),
`docs/assets/` (screenshots supporting conclusions).

**Not included:** any Sony firmware, partition image, `firmware.tar`, `BODYDATA.DAT` or updater;
any library extracted from firmware (`appFw.so`, `libObj.so`, `libMWF.so`, …); any decryption keys;
raw run logs; copies of third-party source.

---

## Technical approach in one paragraph

`/etc/ld.so.preload` loads `/usr/lib/appFwBoot.so`, a shim we wrote. It performs generation-offset
substitution so the 5th-gen `appFw.so` runs on a 4th-gen host; it polls a shared page that the host
writes touch coordinates into and replays them through `postMouseMove/Press/Release`; it injects key
events directly via `g5_send_internal_event`, bypassing the dead 4th-gen input queue; and it carries
a forced-redraw watchdog that repaints when the app's own draw loop stalls.
**No binary patches** are made to `im.elf`, `libObj.so`, `libMWF.so` or `libIMDB.so`.

---

## Known defects (recorded honestly)

### 1. Screen-reader subsystem loops on a failing allocation

The 5th-gen app repeatedly calls `adf_sys_set_text_speech_*`, each time hitting a failed
`dmm alloc_core`:

```
adf_sys_set_text_speech_output  →  dmm alloc_core ERROR(-3)
                                →  dmm_free handle[0xffff]
                                →  adf_sys_set_text_speech_volume
(one round every ~6 s; the UI stops repainting after ~154 s)
```

**Root cause:** the 5th-gen `/share/screenreader` tree (226 MB, ten languages) does not fit in our
300 MiB image and was trimmed.

**Mitigation:** adding an **empty** `/share/screenreader/simplifiedchinese/` directory keeps
`dmm` errors at zero for 240 s of idle menu time (previously they began at 154 s).

**Still open:** switching language makes the engine reload that language's data and re-enters the
same failing path.

See [docs/astra-port/32-stall-root-cause-screenreader.md](docs/astra-port/32-stall-root-cause-screenreader.md).

### 2. Some input actions are ignored

Even with zero `dmm` errors and continuous repainting, individual actions (e.g. the Close button)
may only produce a highlight without changing screens. **"Repaint alive" and "event handling alive"
are separate problems**; the latter is not yet diagnosed.

### 3. `next=0` is not corruption

An early hypothesis that `PCM_OPEN ... next=0x0` meant a corrupted screen stack was wrong: it is the
app's normal way of saying "close the current layer, no replacement". Forcing a real screen id there
breaks dismissal. See [docs/astra-port/29-menu-close-analysis.md](docs/astra-port/29-menu-close-analysis.md).

---

## Recovery channels (why no flashing procedure is offered)

| Channel | Requires | Status |
|---|---|---|
| PMCA service shell | system boots normally | ✅ verified |
| PMCA `updatershell -f` with official firmware | camera enters mass storage | 🟡 tool exists, untested |
| SD card + `BODYDATA.DAT` | camera supports SD updates | ❌ **a6600 does not** (Sony's own procedure says remove the card before updating) |
| Watchdog auto-reset | whole-system hang | ❌ UI frozen 160 s produced no reset |
| UART / BootROM | test points located | ❌ not located |

**⇒ Writing `/etc/ld.so.preload` currently has no verified fallback, so this project provides no
flashing procedure.**

A safer alternative (not implemented): use the camera's 500 MiB `/log` partition plus
`mount --bind` over `/usr/lib/*` so a power cycle restores stock.
See [docs/astra-port/30-recovery-playbook.md](docs/astra-port/30-recovery-playbook.md).

---

## Real-device survey (read-only)

```
/dev/nflasha7  /          ext2  ro      4 MiB
/dev/nflasha15 /usr       ext2  ro    300 MiB   ← plain ext2, not compressed
/dev/nflasha10 /tmp + /etc vfat  rw    12 MiB   ← same device as /tmp
/dev/nflasha11 /log       vfat  rw    500 MiB
/dev/nflasha2  /setting   vfat  rw     20 MiB
/dev/nflasha3  /system    vfat  rw     48 MiB
```

Nothing on the camera was modified; only two partition backups were written to `/log`.

---

## Reading order

1. [docs/astra-port/27-final-handover.md](docs/astra-port/27-final-handover.md) — handover summary
2. [docs/astra-port/28-key-injection-channel.md](docs/astra-port/28-key-injection-channel.md) — key channel and mapping
3. [docs/astra-port/32-stall-root-cause-screenreader.md](docs/astra-port/32-stall-root-cause-screenreader.md) — stall root cause
4. [docs/astra-port/30-recovery-playbook.md](docs/astra-port/30-recovery-playbook.md) — recovery playbook
5. [docs/astra-port/31-firmware-and-sd-recovery.md](docs/astra-port/31-firmware-and-sd-recovery.md) — firmware and SD recovery
6. [docs/00-工作区总览.md](docs/00-工作区总览.md) — earlier ten-section overview (background)

> Documents are numbered by round; **later conclusions overturn earlier ones**. Check the latest
> round and `docs/astra-port/` before citing anything.

---

## What you must supply to reproduce

| Material | How to obtain |
|---|---|
| a6600 official updater | Sony support site (your region) |
| Stock firmware image | Unpack from the updater (unpacking scripts are here, data is not) |
| QEMU with a custom `sony-a6400` machine | Build it; see `scripts/port/patch_qemu_touch.py` |
| ZV-1M2 5th-gen libraries | Obtain lawfully yourself; not provided here, keys not provided either |

Absolute paths in the scripts are replaced with `${WORKSPACE}` / `${REPO}` / `${RUN}`
placeholders; rewrite them for your setup.

---

## Evidence grading

Statements in this project fall into three classes, and the distinction matters:

- **Observation** — logs, screenshots, register readings that can be re-checked
- **Inference** — derived from observations, may be overturned later
- **Incomplete check** — plans, pending items, failed attempts

Failed and retracted conclusions are **kept, not deleted**. Several of our own misjudgements are
documented, including "treated a static frame as a freeze", "treated `next=0` as corruption" and
"treated a stale frame as fresh evidence".

---

## Acknowledgements

### Special thanks: PCIEARIA / A6400-Extra-Menu

[**PCIEARIA/A6400-Extra-Menu**](https://github.com/PCIEARIA/A6400-Extra-Menu) is the **primary supporter**
of this project, and we thank them sincerely:

- **Ongoing technical support and experience sharing** — their debugging insight on the a6xxx platform,
  experiment design, and above all their knowledge of *which approaches do not work* saved this project
  a great deal of time;
- **H100 server compute** — the static analysis and large batch jobs were run on their H100 server.
  Without that compute this project could not have completed several rounds of symbol scanning,
  symbol closure and batch experiments in a reasonable time;
- **Camera root and vulnerability-extraction method** — their PMCA deployment chain and the
  `/etc/a6400-autoexec.so` boot-time mount hook are the direct source of our ability to obtain
  read-only access to a real camera and to verify root reachability. Our conclusions about the
  real device's partition layout and read-only extraction are built on that method.

> `A6400-Extra-Menu` is licensed under **PolyForm Noncommercial 1.0.0**, which is **incompatible with
> GPL-3.0**. This repository therefore **contains none of its code or binaries** — the acknowledgement
> covers support and ideas only. If you want to use their work, follow their original licence.

### Other public research

| Project | Contribution | Licence |
|---|---|---|
| [ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) | Camera service mode, firmware containers | see upstream |
| [ma1co/fwtool.py](https://github.com/ma1co/fwtool.py) | FDAT / SDM structures | see upstream |
| ma1co QEMU branch | a6xxx machine emulation | GPL-2.0 (QEMU) |
| [nolan2628/ZVE10-Astra-Public](https://github.com/nolan2628) | The same idea on ZV-E10; primary reference | see upstream |
| anlock6600 public research | a6600 unpacking and CRC chain conclusions | see original |
| [Oein/a5000-cfw](https://github.com/Oein/a5000-cfw) | Early CFW practice | see upstream |
| [cokeenet/zve10-qemu](https://github.com/cokeenet/zve10-qemu) | The same idea on ZV-E10; **this repository's layout and documentation style follow it** | see upstream |

**No code from any of the projects above is included.** Full attribution and exclusion list:
[NOTICE.md](NOTICE.md).

### Licence

GPL-3.0 throughout — see [LICENSE](LICENSE). No Sony material is included, so no Sony work is
relicensed here.

> **Note:** GPL-3.0 is strongly copyleft. If you merge these scripts or documents into your own
> project and distribute it, the derivative must also be GPL-3.0. Reading, studying or internal use
> is unaffected.

---

*This is a research archive. The authors accept no liability for device damage, voided warranty,
or legal consequences arising from use of these methods.*
