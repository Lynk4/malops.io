# Kernel Shield

---

Categories: Kernel driver

Level: easy

Tools: IDA Pro

Creator: MalOps Team

---

### Scenario

Your organization's incident response team has been called in after a devastating ransomware attack encrypted critical servers across the network. During forensic analysis, the team discovered that the ransomware didn't just encrypt files — it first deployed a malicious kernel driver named 'NSecKrnl' to neutralize all endpoint detection and response (EDR) solutions running on the target machines. By operating at the kernel level, the driver was able to intercept process handle operations, strip security tool access rights, and forcefully terminate any protective processes before the ransomware payload executed. Without EDR visibility, the ransomware operated completely undetected. Your task as a malware analyst is to load this kernel driver into IDA Pro and fully reverse engineer its capabilities. Uncover how it initializes, how it evades kernel integrity checks, how it communicates with its usermode ransomware component via IOCTL codes, and how it systematically kills EDR processes. Your findings will be critical to understanding the full attack chain and building detections to prevent future incidents.

---

### Question 1

**The driver exposes itself to usermode applications under a specific name. What is this name?**

the driver creates a device with the name `\Device\NSecKrnl` and creates a symbolic link `\DosDevices\NSecKrnl` to expose it to usermode applications.

![Screenshot 2026-02-17 at 7.13.10 PM.png](Kernel%20Shield/Screenshot_2026-02-17_at_7.13.10_PM.png)

**Decompiled DriverEntry**

```c
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  _security_init_cookie();
  return sub_14000114C(DriverObject);  // <-- Key: calls initialization function
}
```

**Decompiled the Initialization Function**

```c
RtlInitUnicodeString(&DestinationString, L"\\Device\\NSecKrnl");
RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\NSecKrnl");
...
IoCreateDevice(DriverObject, 0, &DestinationString, 0x22u, 0, 0, &DeviceObject);
IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
```

**Understanding the Windows Driver Model**

In Windows kernel drivers:

- **`\Device\<name>`** - Creates a device object in the kernel namespace
- **`\DosDevices\<name>`** (or `\??\<name>`) - Creates a symbolic link that usermode applications can access
- **`IoCreateSymbolicLink`** - Links the usermode-accessible name to the kernel device

The symbolic link `\DosDevices\NSecKrnl` is what usermode applications use to open a handle to the driver (e.g., via `CreateFile("\\\\.\\NSecKrnl", ...)`).

**Answer:**

```c
NSecKrnl
```

---

### Question 2

**During initialization, the driver tampers with its own loader entry to bypass a kernel security check. What hex value is OR'd into that field?**

During initialization, the driver modifies its own `LDR_DATA_TABLE_ENTRY` structure to bypass kernel security checks. Specifically, it accesses the `DriverSection` field of the `DRIVER_OBJECT` — which points to the driver's loader entry — and OR's the value `0x20` into the flags field:

```c
*((_DWORD *)DriverObject->DriverSection + 26) |= 0x20u;
```

```c
.text:000000014000114C                 push    rbx
.text:000000014000114E                 sub     rsp, 60h
.text:0000000140001152                 mov     rax, [rcx+28h]
.text:0000000140001156                 lea     rdx, aDeviceNseckrnl ; "\\Device\\NSecKrnl"
.text:000000014000115D                 mov     rbx, rcx
.text:0000000140001160                 lea     rcx, [rsp+68h+DestinationString] ; DestinationString
.text:0000000140001165                 or      dword ptr [rax+68h], 20h
.text:0000000140001169                 and     cs:SpinLock, 0
.text:0000000140001171                 call    cs:RtlInitUnicodeString
.text:0000000140001177                 lea     rdx, SourceString ; "\\Do
```

```c
*((_DWORD *)DriverObject->DriverSection + 26) |= 0x20u;
```

Answer:

```c
0x20
```

---

### Question 3

**At what byte offset from the base of the loader data table entry does this tampering occur?**

From the decompiled code:

```c
*((_DWORD*)DriverObject->DriverSection+26)|=0x20u;
```

**Calculation**

- The pointer is cast to `_DWORD *` (a DWORD = **4 bytes**)
- The offset is **+ 26** (in DWORD units)
- So the **byte offset** = `26 × 4 = 104` = **`0x68`**

**LDR_DATA_TABLE_ENTRY structure:**

```c
Offset  Field
0x00    InLoadOrderLinks
0x10    InMemoryOrderLinks
0x20    InInitializationOrderLinks
0x30    DllBase
0x38    EntryPoint
0x40    SizeOfImage
0x48    FullDllName
0x58    BaseDllName
0x68    Flags          <-- ✅ This is where 0x20 is OR'd in
0x6C    ObsoleteLoadCount
...
```

Answer

```c
0x68
```

---

### Question 4

**One of the IOCTL codes handled by the dispatch function leads to forced process termination. What is this code in hex?**

The IOCTL dispatch function (`sub_140001030`) compares the IOCTL code against **4 values**:

| **IOCTL Code (Decimal)** | **IOCTL Code (Hex)** | **Handler Function** | **Action** |
| --- | --- | --- | --- |
| `2246868` | `0x2248D4` | `sub_1400012B8` | Unknown |
| `2246872` | `0x2248D8` | `sub_140001614` | Unknown |
| `2246876` | `0x2248DC` | `sub_140001240` | Unknown |
| **`2246880`** | **`0x2248E0`** | **`sub_1400013E8`** | **ZwTerminateProcess ✅** |

![Screenshot 2026-02-19 at 12.09.09 AM.png](Kernel%20Shield/Screenshot_2026-02-19_at_12.09.09_AM.png)

```nasm
mov  r8d, [rcx+18h]        ; Load the IOCTL code from the IRP stack
sub  r8d, 2248D4h          ; r8d = IOCTL - 0x2248D4
jz   loc_1400010AA         ; if result == 0 → IOCTL was 0x2248D4

sub  r8d, 4                ; r8d = r8d - 4  (i.e. IOCTL - 0x2248D8)
jz   loc_140001093         ; if result == 0 → IOCTL was 0x2248D8

sub  r8d, 4                ; r8d = r8d - 4  (i.e. IOCTL - 0x2248DC)
jz   loc_140001082         ; if result == 0 → IOCTL was 0x2248DC

cmp  r8d, 4                ; is remaining value == 4? (i.e. IOCTL == 0x2248E0?)
jnz  loc_1400010BE         ; if NOT → invalid IOCTL, exit
...
call sub_1400013E8         ; ✅ ZwTerminateProcess handler!
```

The IOCTL that leads to `sub_1400013E8` (which calls `ZwTerminateProcess`) is:

**`0x2248E0`** = `0x2248D4 + 4 + 4 + 4`

Decompiling `sub_1400013E8` clearly shows:

```c
PsLookupProcessByProcessId(a1, &Process);
ObOpenObjectByPointer(Process, ...);
ZwTerminateProcess(ProcessHandle, 0);  // <-- Forced process termination!
ZwClose(ProcessHandle);
```

**Visual Flow**

```c
Imports Tab
    └── ZwTerminateProcess
            │
            X (XREFs)
            │
            └── sub_1400013E8  (calls ZwTerminateProcess)
                        │
                        X (XREFs)
                        │
                        └── sub_140001030  (IOCTL dispatch)
                                    │
                                    cmp [IOCTL], 2246880  ← 0x2248E0
```

Answer

```nasm
0x2248E0
```

---

### Question 5

**When the dispatch function receives an unrecognized IOCTL or a NULL input buffer, it returns a specific NTSTATUS code. What is it in hex?**

![Screenshot 2026-02-19 at 12.12.24 AM.png](Kernel%20Shield/Screenshot_2026-02-19_at_12.12.24_AM.png)

```c
mov  edi, 0C0000001h       ; ← Default return value = 0xC0000001
...
jnz  short loc_1400010BE   ; unrecognized IOCTL → jumps to exit
jz   short loc_1400010BE   ; NULL input buffer → jumps to exit
```

```c
v4 = -1073741823;   // This is 0xC0000001 as a signed int
...
// if unrecognized IOCTL or NULL buffer → returns v4
a2->IoStatus.Status = v4;
IofCompleteRequest(a2, 0);
return v4;
```

This is the standard Windows NTSTATUS code:

| **Value** | **Constant** | **Meaning** |
| --- | --- | --- |
| `0xC0000001` | `STATUS_UNSUCCESSFUL` | Generic failure — operation could not be performed |

The driver sets `0xC0000001` as the **default error code** at the very beginning of the dispatch function, and returns it whenever:

- The IOCTL code is **not recognized** (falls through to `loc_1400010BE`)
- The **input buffer is NULL** (`test r9, r9` → `jz loc_1400010BE`)

Answer

```nasm
0xC0000001
```

### Question 6

**The driver maintains internal tracking arrays with a fixed capacity. How many entries can each array hold?**

In `sub_1400012B8`, the code iterates over an array bounded by two global pointers:

```c
v3 = qword_140003030;          // ← Start of array
while (a1 != *v3) {
    if (++v3 >= qword_140005030)  // ← End of array (boundary check)
        ...
}

```

![Screenshot 2026-02-19 at 12.19.52 AM.png](Kernel%20Shield/Screenshot_2026-02-19_at_12.19.52_AM.png)

- Note the **start address**: `0x140003030`
- Note the **end address**: `0x140005030`
- Subtract: `0x140005030 - 0x140003030 = 0x2000` bytes
- Each entry is a **QWORD = 8 bytes**
- `0x2000 ÷ 8 = 0x400 =` **1024 entries**

Answer

```nasm
1024
```

---

### Question 7

**The driver registers a `kernel callback` to intercept `handle operations` at a specific altitude. What is this `altitude` number?**

- **"kernel callback"** → a function that registers callbacks
- **"handle operations"** → something that intercepts `OpenProcess`, `DuplicateHandle`, etc.
- **"altitude"** → only certain Windows APIs use altitude

**Altitude is ONLY Used by Two APIs in Windows**

| **API** | **What it Does** |
| --- | --- |
| **`ObRegisterCallbacks`** | Intercepts **handle operations** (open/duplicate on processes/threads) |
| **`FltRegisterFilter`** | Intercepts **file system operations** (minifilter driver) |

**General Windows Kernel Knowledge**

```
Type of Callback          │  API Used                │ Has Altitude?
─────────────────────────────────────────────────────────────────────
Process create/exit       │  PsSetCreateProcessNotify │     ❌ No
Image load                │  PsSetLoadImageNotify     │     ❌ No
Handle open/duplicate     │  ObRegisterCallbacks      │     ✅ YES
Registry operations       │  CmRegisterCallback       │     ❌ No
File system (minifilter)  │  FltRegisterFilter        │     ✅ YES
```

Only `ObRegisterCallbacks` and `FltRegisterFilter` use altitudes. 

![Screenshot 2026-02-19 at 10.05.47 AM.png](Kernel%20Shield/Screenshot_2026-02-19_at_10.05.47_AM.png)

**Find XREFs**

- Press **`X`** to see who calls it
- Double-click the only caller → lands you in `sub_140001518`

![Screenshot 2026-02-19 at 10.07.03 AM.png](Kernel%20Shield/Screenshot_2026-02-19_at_10.07.03_AM.png)

**Press F5 to Decompile**

```c
NTSTATUS sub_140001518()
{
  NTSTATUS result; // eax
  PVOID v1; // rcx
  _QWORD v2[4]; // [rsp+20h] [rbp-50h] BYREF
  struct _OB_CALLBACK_REGISTRATION CallbackRegistration; // [rsp+40h] [rbp-30h] BYREF

  v2[0] = PsProcessType;
  v2[1] = 3;
  v2[2] = sub_1400014B0;
  memset(&CallbackRegistration, 0, sizeof(CallbackRegistration));
  v2[3] = 0;
  *(_DWORD *)&CallbackRegistration.Version = 65792;
  RtlInitUnicodeString(&CallbackRegistration.Altitude, L"**328987**"); <--- here 
  CallbackRegistration.RegistrationContext = 0;
  CallbackRegistration.OperationRegistration = (OB_OPERATION_REGISTRATION *)v2;
  result = ObRegisterCallbacks(&CallbackRegistration, &RegistrationHandle);
  v1 = RegistrationHandle;
  if ( result < 0 )
    v1 = 0;
  RegistrationHandle = v1;
  return result;
}
```

Answer

```c
328987
```

---

### Question 8

**When the driver opens a handle to a process it is about to forcefully terminate, what handleattribute value (hex) does it request?**

The question says **"opens a handle to a process it's about to terminate"** so the handle open happens **right before** `ZwTerminateProcess`.

We already have this answer from the earlier decompilation of `sub_1400013E8`

```c
ObOpenObjectByPointer(
    Process,
    0x200u,      // ← HandleAttributes!
    0,
    1u,          // DesiredAccess
    (POBJECT_TYPE)PsProcessType,
    0,
    &ProcessHandle
);
ZwTerminateProcess(ProcessHandle, 0);  // ← then terminates it
```

Decompilatioon

```c
char __fastcall sub_1400013E8(void *a1)
{
  HANDLE ProcessHandle; // [rsp+58h] [rbp+10h] BYREF
  PEPROCESS Process; // [rsp+60h] [rbp+18h] BYREF

  Process = 0;
  ProcessHandle = 0;
  if ( PsLookupProcessByProcessId(a1, &Process) >= 0
    && ObOpenObjectByPointer(Process, **0x200u**, 0, 1u, (POBJECT_TYPE)PsProcessType, 0, &ProcessHandle) >= 0 )
  {
    ZwTerminateProcess(ProcessHandle, 0);
    ZwClose(ProcessHandle);
  }
  if ( Process )
    ObfDereferenceObject(Process);
  return 0;
}
```

```c
PsLookupProcessByProcessId(a1, &Process);  // 1. Get EPROCESS from PID
ObOpenObjectByPointer(                      // 2. Open a handle
    Process,
    0x200u,          // ← HandleAttributes — answer
    0,
    1u,
    PsProcessType,
    0,
    &ProcessHandle
);
ZwTerminateProcess(ProcessHandle, 0);       // 3. Kill it
```

**How to Know What Each Parameter Means**

`ObOpenObjectByPointer` signature:

```
c

NTSTATUSObOpenObjectByPointer(
    PVOIDObject,            // [1] the EPROCESS pointer
    ULONGHandleAttributes,  // [2] ← THIS is what we want
    PACCESS_STATEPassedAccessState, // [3]
    ACCESS_MASKDesiredAccess,     // [4]
    POBJECT_TYPEObjectType,        // [5]
    KPROCESSOR_MODEAccessMode,        // [6]
    PHANDLEHandle             // [7] output handle
);
```

The **2nd parameter** is always `HandleAttributes` → value is **`0x200`** = `OBJ_KERNEL_HANDLE`.

**Visual Flow**

```c
Question: "handle attribute when opening process to terminate"
        ↓
Find ZwTerminateProcess in Imports → X → sub_1400013E8
        ↓
F5 (decompile) → see ObOpenObjectByPointer
        ↓
2nd parameter = HandleAttributes = 0x200
        ↓
Answer: 0x200 (OBJ_KERNEL_HANDLE)
```

Answer

```c
0x200
```

---

### Question 9

**What is the PDB filename embedded in the binary?**

Press **`Shift + F12`** → Opens Strings window

![Screenshot 2026-02-19 at 10.19.55 AM.png](Kernel%20Shield/Screenshot_2026-02-19_at_10.19.55_AM.png)

---

```c
.rdata:000000014000223C                 GUID <0F5B60967h, 0AA22h, 4494h, <0AFh, 73h, 0E6h, 7, 0BFh, 7, 0F1h, \ ; GUID
.rdata:000000014000223C                       0B9h>>
.rdata:000000014000224C                 dd 1                    ; Age
.rdata:0000000140002250                 text "UTF-8", 'D:\NSecsoft\NSec\NSEC-Client-Kernel\Drivers\NSecKrnl\N' ; PdbFileName
.rdata:0000000140002286                 text "UTF-8", 'SecKrnl\bin\NSecKrnl64.pdb',0
.rdata:00000001400022A1                 align 4
.rdata:00000001400022A4 ; Debug information (IMAGE_DEBUG_TYPE_POGO)
.rdata:00000001400022A4 unk_1400022A4   db    0                 ; DATA XREF: .rdata:0000000140002120↑o
.rdata:00000001400022A5                 db    0
```

Answer

```c
NSecKrnl64.pdb
```

---

### Question 10

**The driver creates its device object with a specific device type constant. What is this value in hex?**

The question says **"creates its device object"** → there is only **ONE** API in Windows kernel that creates device objects:

```c
IoCreateDevice(
    DriverObject,      // [1] the driver
    ExtensionSize,     // [2] extra memory
    DeviceName,        // [3] name (\Device\NSecKrnl)
    DeviceType,        // [4] ← WHAT TYPE of device?
    DeviceCharacteristics, // [5]
    Exclusive,         // [6]
    DeviceObject       // [7] output
);
```

We already have this from our earlier decompilation of `sub_14000114C` 

```c
result = IoCreateDevice(
    DriverObject,
    0,
    &DestinationString,
    0x22u,         // ← DeviceType — THIS is the answer
    0,
    0,
    &DeviceObject
);
```

The **4th parameter** is  `DeviceType`.

**Decompiled Code**

```c
NTSTATUS __fastcall sub_14000114C(PDRIVER_OBJECT DriverObject)
{
  NTSTATUS result; // eax
  NTSTATUS v3; // ebx
  struct _UNICODE_STRING DestinationString; // [rsp+40h] [rbp-28h] BYREF
  struct _UNICODE_STRING SymbolicLinkName; // [rsp+50h] [rbp-18h] BYREF
  PDEVICE_OBJECT DeviceObject; // [rsp+70h] [rbp+8h] BYREF

  *((_DWORD *)DriverObject->DriverSection + 26) |= 0x20u;
  SpinLock = 0;
  RtlInitUnicodeString(&DestinationString, L"\\Device\\NSecKrnl");
  RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\NSecKrnl");
  DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&sub_140001010;
  DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&sub_140001010;
  DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&sub_140001030;
  DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_1400010E0;
  result = IoCreateDevice(DriverObject, 0, &DestinationString, 0x22u, 0, 0, &DeviceObject);
  if ( result >= 0 )
  {
    v3 = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
    if ( v3 >= 0 )
    {
      byte_140003010 = PsSetCreateProcessNotifyRoutine(NotifyRoutine, 0) >= 0;
      byte_140003011 = PsSetLoadImageNotifyRoutine(guard_check_icall_nop) >= 0;
      sub_140001518();
    }
    else
    {
      IoDeleteDevice(DeviceObject);
    }
    return v3;
  }
  return result;
}
```

**What `0x22` means** `0x22` = **34** decimal = `FILE_DEVICE_UNKNOWN` 

Visual Flow 

```c
Question: "device type constant used in IoCreateDevice"
        ↓
Imports → IoCreateDevice → X → caller
        ↓
F5 (decompile) → find IoCreateDevice call
        ↓
Count parameters → 4th param = 0x22
        ↓
Answer: 0x22 (FILE_DEVICE_UNKNOWN)
```

Answer

```c
0x22
```

---

### Question 11

**All four IOCTL codes are evenly spaced. What is the stride (difference) between consecutive codes?**

We already have all 4 IOCTL codes from our earlier analysis

| **Order** | **IOCTL Code** | **Handler** |
| --- | --- | --- |
| 1st | **`0x2248D4`** | `sub_1400012B8` |
| 2nd | **`0x2248D8`** | `sub_140001614` |
| 3rd | **`0x2248DC`** | `sub_140001240` |
| 4th | **`0x2248E0`** | `sub_1400013E8` (ZwTerminateProcess) |

```c
0x2248D8 - 0x2248D4 = 0x4
0x2248DC - 0x2248D8 = 0x4
0x2248E0 - 0x2248DC = 0x4
```

**Why Are They Spaced by 4?**

**IOCTL codes follow this formula in Windows:**

```
CTL_CODE(DeviceType, Function, Method, Access)
```

Which expands to:

```
(DeviceType<<16)| (Access<<14)| (Function<<2)| Method
```

The **`Function`** field is bits **2–13** of the IOCTL code.

Since `Function` is shifted left by **2 bits**:

```
Each increment of Function by 1 = increase IOCTL code by 4
```

So consecutive IOCTL codes from the same driver differ by **4** — this is standard Windows IOCTL design.

**Decompiled Code**

```c
__int64 __fastcall sub_140001030(__int64 a1, IRP *a2)
{
  struct _IRP *MasterIrp; // r9
  unsigned int v4; // edi
  char v5; // al

  MasterIrp = a2->AssociatedIrp.MasterIrp;
  v4 = -1073741823;
  if ( a2->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart == 2246868 )
  {
    if ( MasterIrp
      && (unsigned __int8)sub_1400012B8(
                            *(_QWORD *)&MasterIrp->Type,
                            a2,
                            a2->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart - 2246868) )
    {
      v4 = 0;
    }
  }
  else
  {
    if ( a2->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart == 2246872 )
    {
      if ( !MasterIrp )
        goto LABEL_16;
      v5 = sub_140001614(
             *(_QWORD *)&MasterIrp->Type,
             a2,
             a2->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart - 2246872);
    }
    else if ( a2->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart == 2246876 )
    {
      if ( !MasterIrp )
        goto LABEL_16;
      v5 = sub_140001240(
             *(_QWORD *)&MasterIrp->Type,
             a2,
             a2->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart - 2246876);
    }
    else
    {
      if ( a2->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart != 2246880 || !MasterIrp )
        goto LABEL_16;
      v5 = sub_1400013E8(*(_QWORD *)&MasterIrp->Type);
    }
    if ( v5 )
      v4 = 0;
  }
LABEL_16:
  a2->IoStatus.Status = v4;
  IofCompleteRequest(a2, 0);
  return v4;
}
```

**Visual Flow**

```c
Dispatch function (sub_140001030) assembly
        │
        sub r8d, 2248D4h  → first IOCTL
        sub r8d, 4        ← STRIDE visible directly!
        sub r8d, 4        ← STRIDE again!
        cmp r8d, 4        ← STRIDE again!
        │
Answer: stride = 4
```

---

Answer

```c
4
```

---

### Question 12

Before the handle interception callback checks its internal tables, it performs a self-check to avoid interfering when a process operates on itself. What kernel API provides the current process pointer for this comparison?

**Identify the Callback Registration Function**

From the driver's initialization routine (`sub_14000114C` → `sub_140001518`), the driver registers an object manager callback:

```c
RtlInitUnicodeString(&CallbackRegistration.Altitude, L"328987");
CallbackRegistration.OperationRegistration = v2;  // handler = sub_1400014B0
ObRegisterCallbacks(&CallbackRegistration, &RegistrationHandle);
```

![Screenshot 2026-02-19 at 10.44.59 AM.png](Kernel%20Shield/Screenshot_2026-02-19_at_10.44.59_AM.png)

The registered handler is **`sub_1400014B0`**.

Decompiling `sub_1400014B0` (F5 in IDA Pro) reveals:

```c
__int64 __fastcall sub_1400014B0(__int64 a1, __int64 a2)
{
  struct _KPROCESS *v3; // rdi
  HANDLE ProcessId; // rax
  HANDLE CurrentProcessId; // rax

  if ( a2 )
  {
    v3 = *(struct _KPROCESS **)(a2 + 8);
    if ( v3 )
    {
      if ( *(_QWORD *)(a2 + 32) )
      {
        if ( IoGetCurrentProcess() != v3 )
        {
          ProcessId = PsGetProcessId(v3);
          if ( (unsigned __int8)sub_14000138C(ProcessId) )
          {
            CurrentProcessId = PsGetCurrentProcessId();
            if ( !(unsigned __int8)sub_140001330(CurrentProcessId) )
              **(_DWORD **)(a2 + 32) &= ~1u;
          }
        }
      }
    }
  }
  return 0;
}
```

compares the **currently executing process** (`IoGetCurrentProcess()`) against the **target process** (`v3`). If they are the same, the callback returns immediately without modifying access rights — preventing the driver from interfering when a process opens a handle to **itself**.

| **Item** | **Detail** |
| --- | --- |
| **Function analyzed** | `sub_1400014B0` @ `0x1400014B0` |
| **API used** | `IoGetCurrentProcess()` |
| **Purpose** | Returns `EPROCESS*` of current process for pointer comparison |
| **Confirmed via** | Import table + Hex-Rays decompiler output |

In Windows kernel security drivers using `ObRegisterCallbacks`, a **self-check** (process != target) is standard practice to avoid deadlocks and unintended blocking when a process accesses its own handles. The API `IoGetCurrentProcess()` provides the current process pointer for this comparison.

Answer

```c
IoGetCurrentProcess
```

---

### Question 13

**After unregistering the handle interception callback during driver teardown, the registration handle global is set to a specific value. What is it?**

The question mentions two key phrases:

- **"driver teardown"** → look in the `DriverUnload` routine
- **"unregistering the handle interception callback"** → `ObUnRegisterCallbacks`

From our earlier analysis of the initialization function (`sub_14000114C`), we already knew the `DriverUnload` was assigned:

```c
DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_1400010E0;  // ← stored here
```

Everything registered during `DriverEntry` must be **mirrored and cleaned up** during `DriverUnload`:

| **Startup** | **Teardown** |
| --- | --- |
| `IoCreateDevice` | `IoDeleteDevice` |
| `IoCreateSymbolicLink` | `IoDeleteSymbolicLink` |
| `ObRegisterCallbacks` | `ObUnRegisterCallbacks` ← target |

**Analysis**

**Decompile the Unload Routine (`sub_1400010E0`)**

```c
void sub_1400010E0(DRIVER_OBJECT* a1)
{
    if (byte_140003011)
        PsRemoveLoadImageNotifyRoutine(guard_check_icall_nop);

    if (byte_140003010)
        PsSetCreateProcessNotifyRoutine(NotifyRoutine, 1u);  // remove=TRUE

    sub_140001674();    // ← handles ObUnRegisterCallbacks

    RtlInitUnicodeString(&DestinationString, L"\\DosDevices\\NSecKrnl");
    IoDeleteSymbolicLink(&DestinationString);
    IoDeleteDevice(v1);
}
```

**Decompile the Callback Cleanup (`sub_140001674`)**

```c
__int64 sub_140001674()
{
    if (RegistrationHandle)                     // guard against double-unregister
    {
        ObUnRegisterCallbacks(RegistrationHandle);  // safely unregister
        RegistrationHandle = 0;                 // ← set to NULL after unregistering
    }
    return 0;
}
```

---

**Key Finding**

After calling `ObUnRegisterCallbacks`, the global `RegistrationHandle` is explicitly set to **`0`** (NULL).

---

### **Why `0`?**

This is a standard kernel defensive programming pattern:

```c
1. Check:      if (RegistrationHandle)       → avoid double-unregister crash
2. Unregister: ObUnRegisterCallbacks(...)    → safely remove callback
3. Null out:   RegistrationHandle = 0       → prevent use-after-free
```

Setting the handle to `0` serves two purposes:

- **Safety**: Prevents any other code from using a now-invalid handle
- **Idempotency**: The `if (RegistrationHandle)` guard ensures calling the cleanup function twice is safe

In kernel mode, `0` = `NULL` is the universal convention for "this resource has been freed."

**Visual Flow**

```c
Question: "teardown" + "unregistering handle callback"
        ↓
DriverObject->DriverUnload = sub_1400010E0  (from init code)
        ↓
Decompile sub_1400010E0 → calls sub_140001674
        ↓
Decompile sub_140001674 → ObUnRegisterCallbacks + RegistrationHandle = 0
        ↓
Answer: 0 (NULL)
```

> In Windows kernel drivers, resources registered during `DriverEntry` are always cleaned up in `DriverUnload`. After calling `ObUnRegisterCallbacks`, the registration handle global is set to `0` (NULL) — a universal kernel pattern to prevent use-after-free and double-unregister bugs.
> 

Answer

```c
0
```

---

### Question 14

**The handle interception monitors two types of operations simultaneously. What is the combined flag value (decimal) in the operation registration structure?**

The question asks about the **combined flag value** in the `OB_OPERATION_REGISTRATION` structure — the structure used by `ObRegisterCallbacks` to specify which handle operations to intercept.

From our earlier analysis, the callback registration function `sub_140001518` builds this structure before calling `ObRegisterCallbacks`.

**Analysis**

**Decompile `sub_140001518` (Callback Setup)**

```c
v2[0] = PsProcessType;   // Monitor: Process objects
v2[1] = 3;               // Operations: CREATE + DUPLICATE ← answer
v2[2] = sub_1400014B0;   // PreOperation callback handler
v2[3] = 0;               // PostOperation: none

CallbackRegistration.OperationRegistration = v2;
ObRegisterCallbacks(&CallbackRegistration, &RegistrationHandle);
```

**Decoding the Flag Value `3`**

The `Operations` field is a **bitmask** combining:

| **Flag** | **Decimal** | **Binary** | **Meaning** |
| --- | --- | --- | --- |
| `OB_OPERATION_HANDLE_CREATE` | `1` | `01` | Intercept `OpenProcess` / handle creation |
| `OB_OPERATION_HANDLE_DUPLICATE` | `2` | `10` | Intercept `DuplicateHandle` |
| **Combined** | **`3`** | **`11`** | **Both operations** |

```c
1 (CREATE)  =  0b01
2 (DUPLICATE) = 0b10
──────────────────
3 (BOTH)    =  0b11  ← OR'd together
```

The driver monitors **both** handle creation AND handle duplication on process objects. This is a comprehensive handle interception strategy  any attempt by any process to open or duplicate a handle to a monitored process will be intercepted and potentially stripped of `PROCESS_TERMINATE` access.

**Why Both Flags?**

Monitoring only `HANDLE_CREATE` is insufficient because:

- A process could get a `PROCESS_TERMINATE` handle from another process via **`DuplicateHandle`**
- By monitoring both, the driver ensures **no path exists** to gain termination rights on protected processes

> The combined flags value `3` = `OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE`. Setting both flags in `OB_OPERATION_REGISTRATION.Operations` ensures the driver intercepts **all** possible ways to obtain a handle to monitored processes, making its protection comprehensive.
> 

Answer

```c
3
```

---

### **Question 15**

The termination function must release a reference on the process object before returning. What kernel API performs this dereferencing?

The question asks about **releasing a reference** in the **termination function**. This points directly to Windows kernel **object reference counting** a fundamental kernel memory management rule:

> Any API that **looks up** a kernel object increments its reference count. A matching **dereference** call must always follow.
> 

The termination function (`sub_1400013E8`) uses `PsLookupProcessByProcessId` to get a process pointer — this increments the reference count, **obligating** the driver to call `ObfDereferenceObject` before returning.

**Analysis**

**Decompile the Termination Function (`sub_1400013E8`)**

```c
char sub_1400013E8(void *a1)
{
    PEPROCESS Process = 0;
    HANDLE ProcessHandle = 0;

    // Step 1: Look up process — INCREMENTS reference count
    if (PsLookupProcessByProcessId(a1, &Process) >= 0
        && ObOpenObjectByPointer(Process, 0x200u, 0, 1u,
                                 PsProcessType, 0, &ProcessHandle) >= 0)
    {
        ZwTerminateProcess(ProcessHandle, 0);  // Step 2: Kill it
        ZwClose(ProcessHandle);                // Step 3: Close handle
    }

    // Step 4: MUST release reference from PsLookupProcessByProcessId
    if (Process)
        ObfDereferenceObject(Process);         // ← answer

    return 0;
}
```

**Key Finding**

The paired API sequence is:

```
PsLookupProcessByProcessId(pid, &Process)   → ref count +1
        ...do work...
ObfDereferenceObject(Process)               → ref count -1  ← ANSWER
```

---

**Why `ObfDereferenceObject`?**

| **Rule** | **Detail** |
| --- | --- |
| **Reference counting** | Every kernel object has a ref count managed by the Object Manager |
| **`PsLookupProcessByProcessId`** | Increments ref count — caller owns a reference |
| **`ObfDereferenceObject`** | Decrements ref count — releases ownership |
| **Failure to call it** | Kernel memory leak — EPROCESS object never freed |

The `f` in `ObfDereferenceObject` stands for **"fast"** — it's the optimized inline version of `ObDereferenceObject`. Both do the same thing; kernel code typically uses the `f` (fast) variant.

**Standard Paired API Pattern**

```
Lookup API                          Release API
─────────────────────────────────────────────────
PsLookupProcessByProcessId    →    ObfDereferenceObject
PsLookupThreadByThreadId      →    ObfDereferenceObject
ObReferenceObjectByHandle     →    ObfDereferenceObject
ObReferenceObjectByPointer    →    ObfDereferenceObject
```

> `ObfDereferenceObject` is the mandatory cleanup call after `PsLookupProcessByProcessId`. The driver correctly guards it with `if (Process)` to handle cases where the lookup failed — a sign of careful kernel coding practice that prevents both memory leaks and null pointer dereferences.
> 

Answer

```c
ObfDereferenceObject
```

---

### Question 16

**During initialization, the driver registers a notification callback for image loading events. The function registered for this purpose is unusually small. What is its size in bytes (hex)?**

The question mentions:

- **"image loading events"** → `PsSetLoadImageNotifyRoutine`
- **"unusually small"** → a function far smaller than normal

From the initialization routine (`sub_14000114C`):

```c
byte_140003011 = PsSetLoadImageNotifyRoutine(guard_check_icall_nop) >= 0;
```

The registered callback is **`_guard_check_icall_nop`** at `0x140001000`.

**Analysis**

**Function List Reveals the Size**

| **Function** | **Address** | **Size** |
| --- | --- | --- |
| `sub_140001030` | `0x140001030` | `0xAE` (174 bytes) |
| `sub_14000114C` | `0x14000114C` | `0xF4` (244 bytes) |
| **`_guard_check_icall_nop`** | **`0x140001000`** | **`0x3` (3 bytes)** ← |

**Disassembly Confirms It**

```c
_guard_check_icall_nop:
    retn 0          ; the ENTIRE function — just a return
```

One instruction. 3 bytes (`C2 00 00`). The function does **nothing**.

The image load notification callback is a **stub/NOP function** — it accepts the three standard callback parameters (`FullImageName`, `ProcessId`, `ImageInfo`) but immediately returns without any processing.

**Why Register a Do-Nothing Callback?**

This is a deliberate technique:

```
Normal expectation:  PsSetLoadImageNotifyRoutine → real monitoring logic
This driver:         PsSetLoadImageNotifyRoutine → retn 0  (NOP)
```

Possible reasons:

1. **Anti-forensics**: Satisfies checks that enumerate registered callbacks
2. **Misleading analysis**: Makes analysts expect monitoring logic that isn't there
3. **Placeholder**: Reserved for future use in the driver's development

The name `_guard_check_icall_nop` itself contains **"nop"** — a hint that it's intentionally empty.

> The driver registers `_guard_check_icall_nop` (3 bytes, `retn 0`) as its image load notification callback. This stub function is a deliberate design choice — either as an evasion technique or a placeholder — making it one of the smallest valid kernel callbacks possible.
> 

Answer

```c
0x3
```

---

### Question 17

**The address of the function that the driver assigns as its DriverUnload handler is what?**

We already have this from our very first decompilation of `sub_14000114C`

```c
DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_1400010E0;
```

The question says **"DriverUnload handler"** — there is only **one place** this is ever set in a Windows kernel driver:

```c
DriverObject->DriverUnload = <function pointer>;
```

This is always assigned in the **driver initialization function** — the function that `DriverEntry` calls to set up dispatch routines and register callbacks.

**DriverEntry Calls Initialization**

```
NTSTATUSDriverEntry(PDRIVER_OBJECTDriverObject, PUNICODE_STRINGRegistryPath)
{
_security_init_cookie();
returnsub_14000114C(DriverObject);   // ← initialization here
}
```

Decompiling `sub_14000114C` reveals all handler assignments:

```c
// Dispatch routines
DriverObject->MajorFunction[0]  = &sub_140001010;   // IRP_MJ_CREATE
DriverObject->MajorFunction[2]  = &sub_140001010;   // IRP_MJ_CLOSE
DriverObject->MajorFunction[14] = &sub_140001030;   // IRP_MJ_DEVICE_CONTROL

// Unload routine
DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_1400010E0;  // ← ANSWER
```

**Verify the Function**

Navigating to `0x1400010E0` and decompiling confirms it is the teardown routine:

```c
void sub_1400010E0(DRIVER_OBJECT* DriverObject)
{
    // Remove callbacks
    PsRemoveLoadImageNotifyRoutine(guard_check_icall_nop);
    PsSetCreateProcessNotifyRoutine(NotifyRoutine, 1u);
    sub_140001674();              // ObUnRegisterCallbacks

    // Delete device
    RtlInitUnicodeString(&DestinationString, L"\\DosDevices\\NSecKrnl");
    IoDeleteSymbolicLink(&DestinationString);
    IoDeleteDevice(DeviceObject);
}
```

| **Field** | **Value** |
| --- | --- |
| **Handler Address** | `0x1400010E0` |
| **Assigned in** | `sub_14000114C` (init function) |
| **Assignment code** | `DriverObject->DriverUnload = sub_1400010E0` |
| **Verified by** | Decompiling `0x1400010E0` — contains `IoDeleteDevice`, `IoDeleteSymbolicLink`, cleanup calls |

> The `DriverUnload` handler (`0x1400010E0`) is assigned during driver initialization alongside all `MajorFunction` dispatch routines. It performs the reverse of `DriverEntry`: removing callbacks, deleting the symbolic link, and deleting the device object — ensuring clean driver teardown.
> 

Answer

```c
0x1400010E0
```

---

—