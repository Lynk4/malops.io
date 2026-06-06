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

### If you find these writeups useful, consider giving the repo a ⭐.
