# RokRat Loader

---

Categories: Loader

Level: medium

Tools: IDA Pro  x64dbg

Creator: MalOps Team

---

**Challenge link: [https://malops.io/challenges/rokrat-loader](https://malops.io/challenges/rokrat-loader)**

---

## **Scenario:**

aOur Threat Hunting team has detected suspicious network traffic originating from the workstation of a senior research scientist at DefenseTech Industries, a contractor developing next-generation missile defense systems. The suspicious traffic appears to be communicating with command and control C2 servers previously associated with the advanced persistent threat group known as Lazarus. Initial investigation reveals that the researcher recently received what appeared to be a legitimate job application email with a PDF attachment. Upon opening the attachment, a sophisticated loader was executed, which decrypted and deployed a variant of the RokRat remote access trojan. Our Incident Response team has extracted the shellcode loader component from the infected system for analysis. If you like the challenge support us: [https://buymeacoffee.com/malops](https://buymeacoffee.com/malops)

---

### Question 1

**What is the MD5 hash of the binary?**

Answer:

```bash
kant@APPLEs-MacBook-Pro ~/Desktop> md5sum sample
cf28ef5ceda2aa7d7c149864723e5890  sample
kant@APPLEs-MacBook-Pro ~/Desktop> 
```

---

### Question 2

**What is the entry point address of the binary in hex?**

![Screenshot 2026-03-02 at 4.21.28 PM.png](RokRat%20Loader/Screenshot_2026-03-02_at_4.21.28_PM.png)

Answer:

```bash
0x401000
```

---

### Question 3

**What XOR key is used to decrypt the embedded shellcode in hex?**

The binary uses a self-referencing get-EIP technique to locate an embedded encrypted blob at runtime:

```bash
; sub_40157C — get address of embedded blob
call  sub_401583       ; push return addr (0x401581) onto stack
jmp   short 0x401587
; sub_401583
mov   eax, [esp]       ; eax = 0x401581
retn                   ; jump back to 0x401581
; 0x401587
add   eax, 0Ah         ; eax = 0x40158B  ← blob start
retn
```

![Screenshot 2026-03-02 at 4.27.33 PM.png](RokRat%20Loader/Screenshot_2026-03-02_at_4.27.33_PM.png)

The blob at `0x40158B` has the following layout:

| Offset | Size | Value | Description |
| --- | --- | --- | --- |
| +0x00 | 1 byte | `0x29` | XOR key |
| +0x01 | 4 bytes | `0x000D8C00` | Shellcode size |
| +0x05 | … | … | Encrypted shellcode |

`sub_401134` decrypts the shellcode with a single-byte XOR loop:

```bash
char key  = *a1;             // 0x29
int  size = *(int*)(a1 + 1);
byte *data = a1 + 5;
for (int i = 0; i < size; i++)
    data[i] ^= key;

```

```bash
char key  = *a1;             // 0x29
int  size = *(int*)(a1 + 1);
byte *data = a1 + 5;
for (int i = 0; i < size; i++)
    data[i] ^= key;
```

Answer:

```bash
0x29
```

---

### Question 4

**What is the memory protection constant used when allocating memory for the payload in hex?**

![Screenshot 2026-03-02 at 4.36.39 PM.png](RokRat%20Loader/Screenshot_2026-03-02_at_4.36.39_PM.png)

![Screenshot 2026-03-02 at 4.36.24 PM.png](RokRat%20Loader/Screenshot_2026-03-02_at_4.36.24_PM.png)

decompilation of `sub_4012C2`. The relevant line was:

`v7 = ((int (__stdcall *)(_DWORD, int, int, int))v6)(0, v42, 12288, 64);`

This is a `VirtualAlloc` call (resolved via PEB walking):

| Argument | Value | Meaning |
| --- | --- | --- |
| lpAddress | `0` | Let OS choose address |
| dwSize | `v42` | Payload size |
| flAllocationType | `12288` / `0x3000` | `MEM_COMMIT | MEM_RESERVE` |
| **flProtect** | **`64` / `0x40`** | **`PAGE_EXECUTE_READWRITE`** |

The memory protection constant is **`0x40`** (`PAGE_EXECUTE_READWRITE`) — meaning the allocated region is readable, writable, and executable, which is the standard pattern for staging shellcode before executing it.

The `VirtualAlloc` prototype is well-known:

`LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect        // ← 4th argument
);`

So when I saw a 4-argument call returning a pointer that was immediately used as a destination buffer, I recognized it as `VirtualAlloc`. The 4th argument `64` = `0x40` is a standard Windows constant — `PAGE_EXECUTE_READWRITE`.

Answer:

```bash
0x40
```

---

### Question 5

**What is the hash value used to find the VirtualAlloc function in hex?**

![Screenshot 2026-03-02 at 4.43.47 PM.png](RokRat%20Loader/Screenshot_2026-03-02_at_4.43.47_PM.png)

In IDA, trace backwards from what you already know:

**1. You know VirtualAlloc because of the 4 arguments**
Find the call with `(0, size, 0x3000, 0x40)` in the disassembly. In IDA:

- `Alt+T` → search for `3000` or `40h` to find the VirtualAlloc call site

**2. Look at the instruction just before that call**

`push    40h          ; PAGE_EXECUTE_READWRITE
push    3000h        ; MEM_COMMIT|MEM_RESERVE
push    eax          ; size
push    0            ; NULL
call    eax          ; ← eax was set just above this`

**3. Trace where `eax` (the function pointer) came from**
You'll see something like:

`push    0AA7ADB76h   ; ← this is the hash
call    sub_401041   ; resolver`

The argument pushed before calling the resolver **is** the hash.

---

**General rule:**

> In hashbased API resolution, the pattern is always:
`push <hash>` → `call <resolver>` → `call eax`
> 

So whenever you see an indirect `call eax/ebx` that behaves like a Windows API, scroll up a few lines — the hash is the argument to the resolver call right above it.

You can also cross-check by running the hash algorithm yourself. `sub_401041` uses a ROR-11 + uppercase loop over export names. Feed it `kernel32` exports until one hashes to `0xAA7ADB76` — it'll land on `VirtualAlloc`.

Answer:

```bash
0xAA7ADB76
```

---

### Question 6

**How many bits does the DLL name hash algorithm rotate right (ROR) by in hex?**

from `sub_401041`

![Screenshot 2026-03-02 at 4.49.21 PM.png](RokRat%20Loader/Screenshot_2026-03-02_at_4.49.21_PM.png)

```bash
        v8 = v23;
        do
        {
          v9 = __ROR4__(v3, 11);
          v24 = *((char *)&v8->Flink + v7);
          if ( (char)v24 < 97 )
            v3 = v24 + v9;
          else
            v3 = *((char *)&v8->Flink + v7) - 32 + v9;
          ++v7;
        }
        while ( v7 < v6 );
        v10 = v21;
      }
```

The loop hashes the DLL name character by character using **ROR by 11**.

11 decimal = **`0xB`** in hex.

Answer:

```bash
0XB
```

---

### Question 7

**What value is checked to verify a valid PE header in hex?**

decompilation of `sub_401197`:

![Screenshot 2026-03-02 at 4.54.30 PM.png](RokRat%20Loader/Screenshot_2026-03-02_at_4.54.30_PM.png)

```bash
if ( *v6 != 17744 )
    return 190;
```

`4011e4  cmp     dword ptr [eax], 4550h
4011ea  cmovnz  esi, ecx        ; if not "PE\0\0", set error code 0xBE`

- `[eax]` points to the NT headers (base + `e_lfanew`)
- It compares the first DWORD against **`0x4550`** (`"PE\0\0"`)
- If it doesn't match, `cmovnz` loads `ecx` (`0xBE` = error 190) into `esi`, which becomes the return value

So the specific instruction doing the PE validation is the `cmp dword ptr [eax], 4550h` at `0x4011E4`.

Answer:

```bash
0x4550
```

---

### Question 8

**What is the hexadecimal offset value used in the code to access the export directory in the PE file's Optional Header data directory?**

1. `start` calls `sub_401041` → this is the first unknown function, so decompile it
2. `sub_401041` has `fs:30h` → that's PEB access, so it's resolving APIs
3. An API resolver **must** parse PE headers to find exports → so look for PE offset patterns

The offsets `0x3C` and `0x78` are just **standard PE format knowledge**. If you work with malware or shellcode, you memorize these:

- `0x3C` = always `e_lfanew`
- `0x78` = always Export Directory

**If you don't have them memorized**, here's what to do:

1. Open the [PE format spec on Microsoft docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) or search "PE format offsets"
2. When you see a hardcoded offset like `78h` in code that's walking PE structures, just look it up in the spec

**Quick trick:** Anytime you see two sequential memory reads where the first offset is `3Ch`, you know the code is parsing the PE header. The second offset tells you *which* directory entry it's accessing:

- `78h` = Exports
- `80h` = Imports
- `88h` = Resources

![Screenshot 2026-03-04 at 11.08.54 PM.png](RokRat%20Loader/Screenshot_2026-03-04_at_11.08.54_PM.png)

Answer:

```bash
0x78
```

---

### Question 9

**How many API functions are resolved using hashing in the entire binary?**

There are **7** calls to `sub_401041` (the hash resolver) across the binary:

| # | Call site | Hash | API |
| --- | --- | --- | --- |
| 1 | `start+0x13` | `0x5BF3CB8B` | (likely `VirtualProtect` or similar) |
| 2 | `sub_4012C2+0x53` | `0xAA7ADB76` | `VirtualAlloc` |
| 3 | `sub_4012C2+0x70` | `0x234CCD4B` | `memcpy` |
| 4 | `sub_4012C2+0xC2` | `0x234CCD4B` | `memcpy` (again) |
| 5 | `sub_4012C2+0x135` | `0x406FAB8E` | `LoadLibraryA` |
| 6 | `sub_4012C2+0x17E` | `0xE99E570A` | `GetProcAddress` |
| 7 | `sub_4012C2+0x287` | `0x26EB2DC1` | `VirtualFree` |

But note that `0x234CCD4B` (memcpy) is called **twice** with the same hash. So in terms of **unique API functions resolved**: **6**. In terms of **total hash resolution calls**: **7**.

Answer:

```bash
6
```

---

### Question 10

**How many bytes of headers are skipped to reach the start of the decrypted data?**

From the `sub_401134` decompilation we already analyzed:

`v2 = *a1;                    // +0x00: 1 byte  — XOR key
v4 = *(_DWORD *)(a1 + 1);   // +0x01: 4 bytes — size
v5 = (int)(a1 + 5);         // +0x05: data starts here`

**5 bytes** are skipped:

- 1 byte for the XOR key
- 4 bytes for the size (DWORD)

The decrypted data begins at offset `+5` from the blob start.

```bash
int __fastcall sub_401134(char *a1, int *a2)
{
  char v2; // bl
  int v4; // edx
  int v5; // ecx
  _BYTE *v6; // eax
  int v7; // esi
  int result; // eax

  v2 = *a1;
  v4 = *(_DWORD *)(a1 + 1);
  v5 = (int)(a1 + 5);
  if ( v4 )
  {
    v6 = (_BYTE *)v5;
    v7 = v4;
    do
    {
      *v6++ ^= v2;
      --v7;
    }
    while ( v7 );
  }
  result = sub_4012C2(v5, v4, a2);
  if ( result )
    return 13;
  return result;
}
```

Answer:

```bash
5
```