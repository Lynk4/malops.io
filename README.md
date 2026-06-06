# malops.io — Malware Analysis Writeups

![malops.io](https://github.com/user-attachments/assets/a7d92f48-16db-4c09-b1de-5e107e94cce1)

My solutions and full reverse-engineering writeups for the malware analysis challenges on **[malops.io](https://malops.io/)** — a platform with hands-on RE challenges built around real malware techniques.

Each writeup walks through the analysis question by question: where to look, what the disassembly/decompilation shows, and how the answer is derived. Tools used are mostly **IDA Pro**, **Binary Ninja**, and **x64dbg**.

![Platforms](https://img.shields.io/badge/targets-Windows%20%7C%20Linux-blue)
![Tools](https://img.shields.io/badge/tools-IDA%20Pro%20%7C%20Binary%20Ninja%20%7C%20x64dbg-green)
![Challenges](https://img.shields.io/badge/challenges-5-orange)

---

## Challenges

| # | Challenge | Platform | Category | Difficulty | Description | Writeup |
|:-:|-----------|:--------:|----------|:----------:|-------------|:-------:|
| 1 | **Singularity** | 🐧 Linux | Rootkit | Easy | Linux kernel rootkit that hides PIDs/ports and ships an ICMP-triggered reverse shell | [📄 Read](Singularity/README.md) |
| 2 | **Kernel Shield** | 🪟 Windows | Kernel Driver / EDR Killer | Easy | Driver that strips handle rights and force-kills EDR before ransomware runs | [📄 Read](Kernel%20Shield/README.md) |
| 3 | **RokRat Loader** | 🪟 Windows | Shellcode Loader (Lazarus / APT) | Medium | XOR loader using PEB-walk API hashing to deploy the RokRat RAT | [📄 Read](RokRat%20Loader/README.md) |
| 4 | **EquationDrug** | 🪟 Windows | Kernel-Mode Implant | Hard | Memory-only driver doing kernel APC injection into system processes | [📄 Read](EquationDrug/README.md) |
| 5 | **Katz Stealer** | 🪟 Windows | Infostealer | Medium | Broad stealer grabbing browsers, wallets, and apps, exfil over raw TCP | [📄 Read](Katz%20Stealer/README.md) |

---

## 🐧 Singularity

> **Category:** Rootkit · **Platform:** Linux · **Tool:** IDA Pro

A Linux kernel rootkit (`singularity.ko`) recovered from a memory dump of a compromised web server. It hides its own presence, conceals PIDs and TCP ports, and ships a privilege-escalation backdoor.

**Key techniques covered:**
- `init_module` feature dispatch (15 sub-init routines) and self-hiding via `module_hide_current`
- PID hiding (cap of 32) and TCP port hiding (`/proc/net/tcp` hook on port `18081`)
- Privilege escalation via `ftrace` hooks gated behind the magic word `babyelephant`
- ICMP-triggered reverse shell — a magic Echo Request (seq `1999` / `0xCF07`) spawns a `firefox-updater` masquerade connecting back to `192.168.5.128:443`

📄 **[Full writeup →](Singularity/README.md)**

---

## 🪟 Kernel Shield

> **Category:** Kernel Driver / EDR Killer · **Platform:** Windows · **Tool:** IDA Pro · **Difficulty:** Easy

A malicious Windows kernel driver (`NSecKrnl`) deployed by a ransomware crew to blind endpoint security before encryption. It strips handle access rights from protected processes and force-terminates EDR via IOCTL.

**Key techniques covered:**
- `DriverEntry` setup, device/symlink creation, and `LDR_DATA_TABLE_ENTRY` flag tampering (`|= 0x20` at offset `0x68`) to bypass integrity checks
- IOCTL dispatch table (4 evenly-spaced codes, stride `4`) routing to a `ZwTerminateProcess` handler
- `ObRegisterCallbacks` handle interception at altitude `328987`, monitoring CREATE + DUPLICATE (flag `3`)
- A 3-byte NOP image-load callback used as anti-forensics, plus clean teardown patterns
- Embedded PDB path leak: `NSecKrnl64.pdb`

📄 **[Full writeup →](Kernel%20Shield/README.md)**

---

## 🪟 RokRat Loader

> **Category:** Shellcode Loader · **Platform:** Windows · **Tools:** IDA Pro, x64dbg · **Difficulty:** Medium

A 32-bit shellcode loader tied to the **Lazarus** APT, used to decrypt and deploy the **RokRat** RAT after a spear-phishing lure. Demonstrates classic position-independent loader tradecraft.

**Key techniques covered:**
- Get-EIP self-location to find an embedded encrypted blob, then single-byte XOR decryption (key `0x29`)
- Hash-based API resolution via PEB walking — ROR-11 hashing over export names (e.g. `VirtualAlloc` = `0xAA7ADB76`)
- Manual PE parsing: `e_lfanew` (`0x3C`), export directory (`0x78`), `"PE\0\0"` (`0x4550`) validation
- `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` (`0x40`) to stage the decrypted payload

📄 **[Full writeup →](RokRat%20Loader/README.md)**

---

## 🪟 EquationDrug

> **Category:** Kernel-Mode Implant · **Platform:** Windows (32-bit driver) · **Tool:** IDA Pro

A modular, memory-only kernel implant masquerading as a legitimate Microsoft component (`mrxsmbmg.sys` / "Windows NT SMB Manager"). Recovered after a SOC flagged custom TCP C2 traffic from an engineer's workstation.

**Key techniques covered:**
- Driver identification, version forgery, and an OS version gate (`PsGetVersion`, blocks Windows 6+)
- Main routine launched via `PsCreateSystemThread`
- Runtime string decryption with an LCG (`seed 0xAA107FB`, XOR with high word) — recovers `services.exe`, `lsass.exe`, `winlogon.exe`
- Kernel-mode **APC injection** (`KeInitializeApc` + `KeInsertQueueApc`) into system processes
- Shellcode that loads a malicious module (`msvcp73.dll`) via `LoadLibraryW`

📄 **[Full writeup →](EquationDrug/README.md)**

---

## 🪟 Katz Stealer

> **Category:** Infostealer · **Platform:** Windows · **Tool:** Binary Ninja · **Difficulty:** Medium

A broad credential/data stealer (`report_update.exe`) found in an employee's Downloads folder. Harvests browsers, crypto wallets, messaging apps, gaming accounts, and system info, then exfiltrates over raw TCP.

**Key techniques covered:**
- CIS-country geofencing via `GetLocaleInfoA` (`LOCALE_USER_DEFAULT`) and a country-code pointer table
- Hardcoded C2 over TCP — `185.107.74.40:3131` — with a chunked download/upload protocol (`0x1000` chunks)
- Browser injection (Chrome/Edge/Brave) and process-matching loops via `Process32NextW`
- Targeted theft: Chromium cookies, Firefox profiles, Discord (`app-*`), Telegram `tdata`, gaming launchers, Foxmail, Wi-Fi profiles (`netsh wlan show profiles`), and ngrok tokens (`ngrok.yml`)

📄 **[Full writeup →](Katz%20Stealer/README.md)**

---

## Repository Layout

```
.
├── Singularity/        # Linux rootkit writeup + screenshots
├── Kernel Shield/      # Windows EDR-killer driver writeup + screenshots
├── RokRat Loader/      # Lazarus shellcode loader writeup + screenshots
├── EquationDrug/       # Windows kernel implant writeup + screenshots
└── Katz Stealer/       # Windows infostealer writeup + screenshots
```

Every challenge folder contains a `README.md` with the full question-by-question analysis and supporting screenshots.

---

## ⚠️ Disclaimer

These writeups are for **educational and defensive security research** only. No malware samples or binaries are distributed in this repository — only analysis notes, decompilation excerpts, and screenshots. All challenges originate from **[malops.io](https://malops.io/)**. Use this knowledge responsibly and legally.

---

## 🔗 Links

- 🌐 Challenge platform: **[malops.io](https://malops.io/)**
- ☕ Support the creators: **[buymeacoffee.com/malops](https://buymeacoffee.com/malops)**

If you find these writeups useful, consider giving the repo a ⭐.
