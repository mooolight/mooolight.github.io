---
title: Reversing Gargoyle 
date: 2025-05-29 12:00:00 -500
categories: [Malware, Evasion]
tags: [Reversing]
---

# What is Gargoyle?

Gargoyle is a malware evasion technique that hides in plain sight (from an AV perspective). Unlike traditional malware, Gargoyle understands that AVs and EDRs will trigger to do memory scanning given some suspicious event or action from a process which in this case is process injection. AVs will do memory scan on the suspicious process' executable region which Gargoyle utilize. Gargoyle will create some kind of detour equivalent into "turning into stone" during the time window the process' executable region is being scanned by the AV.

- In this post, I will dive into my process of reversing Gargoyle technique, break down how it operates, how it hides along with the data structures used.

# Setting Up The Analysis Environment

- OS: Windows 10 VM
- Tools: x64dbg, Process Hacker
- Goal: To view Gargoyle technique at the lower-level (assembly)


# Reversing Gargoyle

<u>Structures</u>:
```c
1) rop_gadget_candidates // this is a vector
2) SetupConfiguration
3) StackTrampoline
4) Workspace
```


<u>Functions</u>:
```c
1) main
2) launch
3) tie // this is a tuple
4) get_gadget
5) allocate_workspace
6) setup_memory // Gargoyle PIC
```


<u>Setup</u>:
- Set the Windows SDK version to the most updated one.

- Add the `nasm.exe` on your system environment variable path:

- Setup the compilation for the `.nasm` file to `.obj`:

```c
nasm -f win32 "C:\Users\<user>\Documents\gargoyle-master\gargoyle-master\setup.nasm" -o "C:\Users\<user>\Documents\gargoyle-master\gargoyle-master\setup.obj"
```


### `1)` Main function:

![](/assets/img/Pasted image 20250601103138.png)


- Reached the actual `main()` function:

```c
int main() {
  try {
      __debugbreak();
    launch("setup.pic", "mshtml.dll", "gadget.pic");
  } catch (exception& e) {
    printf("%s\n", e.what());
  }
}
```


- Here's where the argument for `launch()` function is set:

![](/assets/img/Pasted image 20250601151552.png)


What's the `call` to some address prior to each of the pushed argument?
- This is for `string creation`.

- Where are the strings located?

![](/assets/img/Pasted image 20250601151939.png)


- If I follow the newly pushed addresses in stack, you'll see in dump that its a pointer to the string arguments:

![](/assets/img/Pasted image 20250601152241.png)


<u>String pointers</u>: `0xb3faf8` is the value of the current stack pointer

![](/assets/img/Pasted image 20250601152517.png)

- From dump:

![](/assets/img/Pasted image 20250601152638.png)

![](/assets/img/Pasted image 20250601152623.png)

![](/assets/img/Pasted image 20250601152610.png)


### `2)` Delving into `launch()` function (along with its helper functions):

- First part of the `launch()` function which has the `allocate_pic()` helper function

```c
void launch(const string& setup_pic_path, const string& gadget_system_dll_filename, const string& gadget_pic_path) {
	printf("[ ] Allocating executable memory for \"%s\".\n", setup_pic_path.c_str()); // 1st printf
	void* setup_memory; size_t setup_size;
	__debugbreak();
	tie(setup_memory, setup_size) = allocate_pic(setup_pic_path);
	printf("[+] Allocated %d bytes for PIC.\n", setup_size);
```


- First `printf()`:

![](/assets/img/Pasted image 20250601153411.png)

	- Value of eax is 'setup.pic'

![](/assets/img/Pasted image 20250601155637.png)


- Setting up the argument for `tie(setup_memory, setup_size)` tuple creation:

![](/assets/img/Pasted image 20250601153640.png)

	- Actual pointer to the string is at [ebp-130]
	- push ecx == setup_size // 2nd param
	- push eax == setup_memory // 1st param


![](/assets/img/Pasted image 20250601154714.png)

```c
ebp = 00B3FAF0 - 130 = B3 F9C0
```

![](/assets/img/Pasted image 20250601153819.png)

	- This is NOT the 'allocate_pic()' function call then as it doesnt have the pointer to the string that have the value of 'setup.pic'
	- The address B3 F9C0 is the variable setup_size 


However, this is for the `tuple` creation (`tie(setup_memory, setup_size)`):

![](/assets/img/Pasted image 20250601154241.png)

	- This shows that creation of a tuple underneath still requires a subroutine.
	- This specific call is for the 'setup_size' variable.


There is allocation of 8 bytes for the next `call` instruction:

![](/assets/img/Pasted image 20250601154842.png)

	- What is this 8 bytes for?


Peeking the next `call` instruction:

![](/assets/img/Pasted image 20250601155145.png)

	- It is also a `tuple` subroutine. I can assume that this is the subroutine call for accepting the first argument of tie() function as it previously requires 8 bytes allocation for the pointer 'setup_memory'


Why would there be 3 `push` instructions just to allocate a pointer to a tuple?
- Remember that each block in stack has a size of 4 bytes.
- This should be the allocated data in stack where the address to which the pointer will hold onto be placed.

After the 2nd tuple creation `call` instruction, it returns this value on `eax`:

![](/assets/img/Pasted image 20250601155727.png)

![](/assets/img/Pasted image 20250601155718.png)

Checking this address:

![](/assets/img/Pasted image 20250601155817.png)

	- Its an address in stack.
	- This shows the contiguous block containing the pointer "setup_memory" and the size_t variable setup_size

![](/assets/img/Pasted image 20250601160007.png)


- The next one allocates 12 bytes of data for both parameters:

![](/assets/img/Pasted image 20250601155727.png)

	- Placing the eax to ecx shows the 1st argument contains the starting address both of the variables.


Peeking what's the next `call` instruction:

![](/assets/img/Pasted image 20250601160419.png)

	- Also a tuple! This shows that tuple needs 3 'call' instructions for the structure to be created!


### 3. The `call` instruction is a `printf()` function. Where is the `allocate_pic()` function call then? Is it inside the last `tuple creation` function?
- Trying to run it instead: (don't forget to add `__debugbreak()` at the start of `allocate_pic()`)

![](/assets/img/Pasted image 20250601162020.png)

	- This one is already inside `allocate_pic()`


Locating the reference to this function:

![](/assets/img/Pasted image 20250601162052.png)

	- The first instruction right after the last 'int3' leads to some tuple() function... There were three from the 'launch()'. Which one in there leads to 'allocate_pic()'?


Check the reference to this call too recursively:

![](/assets/img/Pasted image 20250601162203.png)


This lead to the first `call` instruction:

![](/assets/img/Pasted image 20250601162243.png)

<u>Conclusion</u>:

- This shows that the last `two` tuple creation `call` subroutines are for assigning the value to the tuple while the first one is for generating those structures through `allocate_pic()`.


# Delving into `allocate_pic()` function

![](/assets/img/Pasted image 20250601162450.png)


- `allocate_pic()` function from C/C++:

```c
MyTuple allocate_pic(const string& filename) {
	__debugbreak();
	fstream file_stream{ filename, fstream::in | fstream::ate | fstream::binary };
	if (!file_stream) throw runtime_error("[-] Couldn't open \"" + filename + "\".");
	auto pic_size = static_cast<size_t>(file_stream.tellg());
	file_stream.seekg(0, fstream::beg);
	auto pic = VirtualAllocEx(GetCurrentProcess(), nullptr, pic_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pic) throw runtime_error("[-] Couldn't VirtualAllocEx: " + GetLastError());
	file_stream.read(static_cast<char*>(pic), pic_size);
	file_stream.close();
	DWORD old_protection;
	auto prot_result = VirtualProtectEx(GetCurrentProcess(), pic, pic_size, PAGE_EXECUTE_READ, &old_protection);
	if (!prot_result) throw runtime_error("[-] Couldn't VirtualProtectEx: " + GetLastError());
	return MyTuple(pic, pic_size);
}
```


### 4. Call to `file_stream`: there are two arguments - the filename to be streamed along with the flags for it

![](/assets/img/Pasted image 20250601162932.png)

	- [EBP+C] == BE F658


![](/assets/img/Pasted image 20250601163021.png)


Checking the value for:

```c
fstream::in == 0x1 // for reading
| 
fstream::ate == 0x40 // move to the end of file after opening
| 
fstream::binary == 0x25 // opens in binary mode
```


First `call` instruction:

![](/assets/img/Pasted image 20250601163214.png)


Stack prior to call:

![](/assets/img/Pasted image 20250601164419.png)


![](/assets/img/Pasted image 20250601164509.png)

	- From a blind reversing perspective, this shows that this process is opening a file 


- Moving onto the execution of `seekg()` function:

![](/assets/img/Pasted image 20250601165103.png)


```c
1st arg: 0
2nd arg: fstream::beg // its a position indicator constant (0x00) - beginning of the file
```


- Next function call: 

```c
auto pic = VirtualAllocEx(GetCurrentProcess(),      // 
						  nullptr,                  // push 0
						  pic_size,                 // push 0x95 == 149 bytes
						  MEM_COMMIT | MEM_RESERVE, // push 0x3000
						  PAGE_EXECUTE_READWRITE);  // push 0x40
```

	- Output of GetCurrentProcess() == -1 which is the handle to the current process


In assembly:

![](/assets/img/Pasted image 20250601165626.png)


Output on `eax`:

![](/assets/img/Pasted image 20250602030941.png)


Base address of the allocated region of pages:
```c
01060000
```

![](/assets/img/Pasted image 20250602031213.png)


- `read()` function:

```c
file_stream.read(static_cast<char*>(pic), pic_size);
```

![](/assets/img/Pasted image 20250602031605.png)


Arguments:

![](/assets/img/Pasted image 20250602031623.png)

	- pic_size == 0x95
	- 'pic' string == to be stored at 0x01060000



- Call to `VirtualProtectEx`:

```c
auto prot_result = VirtualProtectEx(GetCurrentProcess(), pic, pic_size, PAGE_EXECUTE_READ, &old_protection);


Prototype:
BOOL VirtualProtectEx(
	[in] HANDLE hProcess,       // -1
	[in] LPVOID lpAddress,      // 0x01060000
	[in] SIZE_T dwSize,         // 0x95
	[in] DWORD flNewProtect,    // 0x20
	[out] PDWORD lpflOldProtect // 0x00D3F824 => A place in stack where the result of this will be stored which is the previous protection
)
```


`GetCurrentProcess()`:

![](/assets/img/Pasted image 20250602032109.png)

From Stack:

![](/assets/img/Pasted image 20250602032118.png)


Overall arguments:

![](/assets/img/Pasted image 20250602032144.png)


Breakdown of the `flNewProtect` flag:

```c
0x20 == PAGE_EXECUTE_READ
```


Where `oldProtect` will be stored:

![](/assets/img/Pasted image 20250602032800.png)

##### <u>After allocating data on memory for the 'setup.pic'</u>:

![](/assets/img/Pasted image 20250602034049.png)


### 5. Proceeding to `get_gadget()` function:

Caller to `get_gadget()`:

```c
	auto use_system_dll{ true };
	printf("[ ] Configuring ROP gadget.\n");
	__debugbreak();
	auto gadget_memory = get_gadget(use_system_dll, gadget_system_dll_filename, gadget_pic_path);
	printf("[+] ROP gadget configured.\n");
```


##### Current state:

![](/assets/img/Pasted image 20250602034111.png)


# Delving into `get_gadget()` function:

```c
void* get_gadget(bool use_system_dll, const string& gadget_system_dll_filename, const string& gadget_pic_path) {
	__debugbreak();
	void* memory;
	if (use_system_dll) {
		memory = get_system_dll_gadget(gadget_system_dll_filename);
	}
	if (!use_system_dll || !memory) {
		printf("[ ] Allocating executable memory for \"%s\".\n", gadget_pic_path.c_str());
		size_t size;
		tie(memory, size) = allocate_pic(gadget_pic_path);
		printf("[+] Allocated %u bytes for gadget PIC.\n", size);
	}
	return memory;
}
```


This function accepts THREE arguments:

![](/assets/img/Pasted image 20250602033117.png)

![](/assets/img/Pasted image 20250602033223.png)


Prototype for `get_gadget()`:

```c
void* get_gadget(
	bool use_system_dll,                        // is set to 1 so it shows the gadget is on a DLL
	const string& gadget_system_dll_filename,   // filename of the DLL
	const string& gadget_pic_path)              // filename for the gadget position independent code
```


Following DWORD in dump for the 2nd argument `0x00D3FAC4`:

![](/assets/img/Pasted image 20250602033538.png)

Following DWORD in dump for the 3rd argument `0x00D3F928`:

![](/assets/img/Pasted image 20250602033637.png)


- Condition if the gadget is located in a DLL:

```c
if (use_system_dll) {
	memory = get_system_dll_gadget(gadget_system_dll_filename);
}
```

![](/assets/img/Pasted image 20250602033953.png)


# Delving into `get_system_dll_gadget` function:

```c
void* get_system_dll_gadget(const string& system_dll_filename) {
__debugbreak();
  printf("[ ] Loading \"%s\" system DLL.\n", system_dll_filename.c_str());
  auto dll_base = reinterpret_cast<uint8_t*>(LoadLibraryA(system_dll_filename.c_str()));
  if (!dll_base) throw runtime_error("[-] Couldn't LoadLibrary: " + GetLastError());
```

Assembly form:

![](/assets/img/Pasted image 20250602042418.png)

Arguments from stack:

![](/assets/img/Pasted image 20250602042534.png)


Output to `eax`:

![](/assets/img/Pasted image 20250602042704.png)

Handle to the module `mshtml.dll`: `0x5f270000`

![](/assets/img/Pasted image 20250602043031.png)


- `if` statement:

```c
  if (!dll_base) throw runtime_error("[-] Couldn't LoadLibrary: " + GetLastError());
```

Assembly form:

![](/assets/img/Pasted image 20250602043120.png)

	- call gargoyle.971951 is the 'runtime_error()' function.


##### Current State: Successfully loaded the `mshtml.dll`

![](/assets/img/Pasted image 20250602060813.png)

	- The next move is to find the gadget inside this module...


- Moving onto `ImageNtHeader`: structures in a PE image and returns a pointer to the data

```c
  printf("[+] Loaded \"%s\" at 0x%p.\n", system_dll_filename.c_str(), dll_base);

  __debugbreak();
  auto pe_header = ImageNtHeader(dll_base);
  if (!pe_header) throw runtime_error("[-] Couldn't ImageNtHeader: " + GetLastError());
```


Call to `ImageNtHeader`:

![](/assets/img/Pasted image 20250602043338.png)

`[ebp-14]`:

![](/assets/img/Pasted image 20250602043354.png)

![](/assets/img/Pasted image 20250602043420.png)


From the `Memory Map`:

![](/assets/img/Pasted image 20250602043450.png)

	- This module is on read-only mode and has a size of 0x1000


Return value:

![](/assets/img/Pasted image 20250602043855.png)

- `if` statement for error:

![](/assets/img/Pasted image 20250602043938.png)


- Moving onto `FileHeader` parsing:

```c
  __debugbreak();
  auto filtered_section_headers = vector<PIMAGE_SECTION_HEADER>();
  auto section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(pe_header + 1);
  for (int i = 0; i < pe_header->FileHeader.NumberOfSections; ++i)
  {
    if (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
      filtered_section_headers.push_back(section_header);
      printf("[ ] Found executable section \"%s\" at 0x%p.\n", section_header->Name, dll_base + section_header->VirtualAddress);
    }
    section_header++;
  };
```


Setting the initialized value for "`filtered_section_headers`":

![](/assets/img/Pasted image 20250602055205.png)

	- Variable 'filtered_section_headers' is in [ebp-20]. This is an empty vector at this point
	- Variable 'section_header' is in [ebp-44] which holds the address to the 'pe-header' which is the start of mshtml.dll module.


***Note: `IMAGE_SECTION_HEADER` has size of 40 bytes.***

<u>Prototype</u>:

```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```


`[ebp-20]` == `00EFF900`:

![](/assets/img/Pasted image 20250602055529.png)

	- In stack


From dump:

![](/assets/img/Pasted image 20250602055546.png)


`F8` == `248 bytes` ; `[ebp-20] + 0xf8`

![](/assets/img/Pasted image 20250602055810.png)


- Points to some address in `.text` section which is the start of the `mshtml.dll` module:

![](/assets/img/Pasted image 20250602055854.png)

- Got zeroed out after ***`6 bytes`***?

![](/assets/img/Pasted image 20250602055205.png)

	- [ebp-50] == '\0'


- Entering the first `for()` loop:

![](/assets/img/Pasted image 20250602060630.png)


`for` loop statement: leafing through the `FileHeader` of the module

```c
  for (int i = 0; i < pe_header->FileHeader.NumberOfSections; ++i)
```


Comparison instruction:

```c
009826B | 394D B0  | cmp dword ptr ss:[ebp-50], ecx 
009826B | 7D 40    | jge gargoyle.982701  
```

	- The current value for 'ECX' is 6. This shows that there are 6 sections in the header of 'mshtml.dll' module.
	- 0 < 6 so it wont take the jump


![](/assets/img/Pasted image 20250602061507.png)


`[ebp-50]` value:

```c
EF F8D0
```

![](/assets/img/Pasted image 20250602061316.png)


`if` statement inside the first `for()` loop: Finds the ***executable*** section in the current header

```c
...
    if (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
    ...
```



Equivalent assembly form:

```c
009826C | 8B48 24       | mov ecx,dword ptr ds:[eax+24]
009826C | 81E1 00000020 | and ecx,20000000
```


- `section_header->Characteristics` is stored at **`dword ptr ds:[eax+24]`**:

![](/assets/img/Pasted image 20250602062244.png)

	- Size of "section_header->Characteristics" == 4 bytes



`AND` instruction:

```c
(00 00 00 00 20 00 00 60) & (20 00 00 00) == 0x20000000
```


Inside the `if()` statement:

![](/assets/img/Pasted image 20250602063725.png)


Push back to the section header that is executable:

```c
      filtered_section_headers.push_back(section_header);
```

![](/assets/img/Pasted image 20250602063947.png)

Value of `eax` after the call instruction:

![](/assets/img/Pasted image 20250602065047.png)


Checking the value pushed back to the `filtered_section_headers`:

`[ebp-44]` holds the `section_header` value:

![](/assets/img/Pasted image 20250602064251.png)

`filtered_section_headers` vector: pointer to the vector is stored at `[ebp-38]`

![](/assets/img/Pasted image 20250602064537.png)



- Moving onto the searching of gadget in the module:

```c
  __debugbreak();
  for (auto section_header : filtered_section_headers)
  {
    for (auto& rop_gadget : rop_gadget_candidates)
    {
      __debugbreak();
      auto section_base = dll_base + section_header->VirtualAddress;
      vector<uint8_t> section_content(section_base, section_base + section_header->Misc.VirtualSize);
      auto search_result = search(begin(section_content), end(section_content), begin(rop_gadget), end(rop_gadget));
      if (search_result == end(section_content))
          continue;

      auto rop_gadget_offset = section_base + (search_result - begin(section_content));
      printf("[+] Found ROP gadget in section \"%s\" at 0x%p.\n", section_header->Name, rop_gadget_offset);
      return rop_gadget_offset;
    }
  }

  printf("[-] Didn't find ROP gadget in \"%s\".\n", system_dll_filename.c_str());
  return 0;
}
```

	- Find the 'if()' statement inside the inner for() loop when reversing instead of going through each of the iteration.


<u>Continue here</u>:

![](/assets/img/Pasted image 20250602081227.png)


### Fast forward to full execution...


<u>Fully Functional Gargoyle</u>:

![](/assets/img/Pasted image 20250619073500.png)


```c
a) Gargoyle PIC @ -----> 0x01530000
b) ROP gadget @ -------> 0x600A6FA6
c) Configuration @ ----> 0x03600000
d) Top of stack @ -----> 0x03600038
e) Bottom of stack @ --> 0x03610037
f) Stack trampoline @ -> 0x03610038
```


<u>From x32dbg</u>:

`a)` Gargoyle PIC @ `-----> 0x01530000`

![](/assets/img/Pasted image 20250603054527.png)

From Disassembly:

![](/assets/img/Pasted image 20250603054634.png)


Actual Gargoyle PIC:

![](/assets/img/Pasted image 20250603054726.png)

	- Notice the first 3 'push 0' instructions are for Creating the timer.


`b)` ROP gadget @ `-------> 0x600A6FA6`

![](/assets/img/Pasted image 20250603054810.png)

![](/assets/img/Pasted image 20250603054839.png)


`c)` Configuration @ `----> 0x03600000`

![](/assets/img/Pasted image 20250603055219.png)

	- There's 49 bytes in this which completely maps the "SetupConfiguration" data structure!


Structure for this configuration:

```c
  struct SetupConfiguration {
    uint32_t initialized;         // 00 00 00 01
    void* setup_address;          // 01 53 00 00
    uint32_t setup_length;        // 00 00 00 95
    void* VirtualProtectEx;       // 76 90 63 b0
    void* WaitForSingleObjectEx;  // 76 8F 37 80
    void* CreateWaitableTimer;    // 76 92 A8 A0
    void* SetWaitableTimer;       // 76 8F 37 30
    void* MessageBox;             // 75 81 11 00
    void* tramp_addr;             // 03 61 00 38
    void* sleep_handle;           // 00 00 02 20
    uint32_t interval;            // 00 00 3a 98
    void* target;                 // 60 0A 6f A6
    uint8_t shadow[8]; // 1 byte  - 0x20
  };
```

	- Total size of it: 12 + 1 byte == 13 byte + (9*4) = 13 + 36 bytes = 49 bytes in total for this configuration


Example that this indeed leads to the function's starting address:

```c
...
    void* VirtualProtectEx;       // 76 90 63 b0
...
```

![](/assets/img/Pasted image 20250603060029.png)

	- Looking at the starting address == '769063b0' matches!


`d)` Top of stack @ `-----> 0x03600038`

![](/assets/img/Pasted image 20250603060406.png)

	- Top of the allocated memory for the stack


`e)` Bottom of stack @ `--> 0x03610037`

![](/assets/img/Pasted image 20250603060620.png)


`f)` Stack trampoline @ `-> 0x03610038`

Structure of the stack:

```c
struct StackTrampoline {
    void* VirtualProtectEx; // 90 63 b0 00 
    void* return_address;   // 53 00 00 76
    void* current_process;  // ff ff ff 01
    void* address;          // 53 00 00 ff
    uint32_t size;          // 00 10 00 01
    uint32_t protections;   // 00 00 20 00
    void* old_protections_ptr; // 61 00 54 00
    uint32_t old_protections;  // 00 00 02 03
    void* setup_config;        // 60 00 00 00
};
```


# Using `VMMap` tool:

- Using `VMMap` to check these memory addresses:

![](/assets/img/Pasted image 20250603054200.png)

	- The memory region allocated for Gargoyle is executable since the MessageBox is active!


When the `MessageBox` is inactive, its only in `Read` permissions:

![](/assets/img/Pasted image 20250603054248.png)


# Conclusion

Gargoyle is an effective evasion technique given an AV that only rely on scanning executable memory region. However, this technique can be detected by scanners that scan the whole memory region regardless of permission.


# Reference

- VX-Underground
- Sektor7
