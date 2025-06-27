---
title: Reversing Ekko
date: 2025-06-19 12:00:00 -500
categories: [Malware, Evasion]
tags: [Reversing]
---

# What is Ekko?

Similar to Gargoyle, Ekko is a malware evasion technique as well that relies on a time window to wait before it modifies the payload's memory region as executable again and then proceeding to actual execution instead of a detour.


# Reversing Ekko

```c

#include <windows.h>
#include <stdio.h>

#define _CRT_RAND_S
#include <stdlib.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

typedef struct {
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING ;
```


### `1)` Going through the `main()` function:

```c
int main(void) {
    
	puts( "[*] Ekko Sleep Obfuscation by C5pider" );
	
	printf("Module addr: %p\n", GetModuleHandle(NULL));
    do {
        // Start Sleep Obfuscation
        EkkoObf( 7 * 1000 );
		
    } while ( TRUE );

    return 0;
}
```

![](/assets/img/Pasted image 20250603141015.png)


Address stored in `rcx`:

![](/assets/img/Pasted image 20250603141141.png)


In dump:

![](/assets/img/Pasted image 20250603141158.png)


- `7000` == `0x1B58` so `EkkoObf(7000)`

![](/assets/img/Pasted image 20250603141248.png)


### `2)` Entering ***`EkkoObf`***:

```c
VOID EkkoObf( DWORD SleepTime )
{
    CONTEXT CtxThread   = { 0 };

    CONTEXT RopProtRW   = { 0 };
    CONTEXT RopMemEnc   = { 0 };
    CONTEXT RopDelay    = { 0 };
    CONTEXT RopMemDec   = { 0 };
    CONTEXT RopProtRX   = { 0 };
    CONTEXT RopSetEvt   = { 0 };
```



Here's the ***`CONTEXT`*** structure: 32-bit has `716 bytes` and 64-bit has `1232 bytes == 0x4d0`

```c
typedef struct _CONTEXT {
  DWORD64 P1Home;
  DWORD64 P2Home;
  DWORD64 P3Home;
  DWORD64 P4Home;
  DWORD64 P5Home;
  DWORD64 P6Home;
  DWORD   ContextFlags;
  DWORD   MxCsr;
  WORD    SegCs;
  WORD    SegDs;
  WORD    SegEs;
  WORD    SegFs;
  WORD    SegGs;
  WORD    SegSs;
  DWORD   EFlags;
  DWORD64 Dr0;
  DWORD64 Dr1;
  DWORD64 Dr2;
  DWORD64 Dr3;
  DWORD64 Dr6;
  DWORD64 Dr7;
  DWORD64 Rax;
  DWORD64 Rcx;   // need this
  DWORD64 Rdx;   // need this
  DWORD64 Rbx;
  DWORD64 Rsp;   // need this
  DWORD64 Rbp;
  DWORD64 Rsi;
  DWORD64 Rdi;
  DWORD64 R8;   // need this
  DWORD64 R9;   // need this
  DWORD64 R10;
  DWORD64 R11;
  DWORD64 R12;
  DWORD64 R13;
  DWORD64 R14;
  DWORD64 R15;
  DWORD64 Rip;   // need this
  union {
    XMM_SAVE_AREA32 FltSave;
    NEON128         Q[16];
    ULONGLONG       D[32];
    struct {
      M128A Header[2];
      M128A Legacy[8];
      M128A Xmm0;
      M128A Xmm1;
      M128A Xmm2;
      M128A Xmm3;
      M128A Xmm4;
      M128A Xmm5;
      M128A Xmm6;
      M128A Xmm7;
      M128A Xmm8;
      M128A Xmm9;
      M128A Xmm10;
      M128A Xmm11;
      M128A Xmm12;
      M128A Xmm13;
      M128A Xmm14;
      M128A Xmm15;
    } DUMMYSTRUCTNAME;
    DWORD           S[32];
  } DUMMYUNIONNAME;
  M128A   VectorRegister[26];
  DWORD64 VectorControl;
  DWORD64 DebugControl;
  DWORD64 LastBranchToRip;
  DWORD64 LastBranchFromRip;
  DWORD64 LastExceptionToRip;
  DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;
```


### `3)` Call to the first `CONTEXT` structure **`CtxThread`**:

![](/assets/img/Pasted image 20250603143741.png)

	- A good indicator that this `call` instruction is of CONTEXT structure creation is the '0x4d0' value as the CONTEXT structure for 64-bit has the size of 1232 bytes in decimal and 0x4d0 in hex.
	- In the code, it showed that there are supposed to be SEVEN CONTEXT structures which matches whatever is in the instructions above.


##### Checking the internals of the `CONTEXT` structure

### `4)` Parameters to this `call` instruction:

```c
- rcx : 0000004D0AAFD5A0 // probably the pointer to the starting address of the structure
- rdx : 0  // Could be the initialized value? After all, the 'CONTEXT' structures are nulled? {0}
- r8 : 4d0 // contains the size of the structure
- r9 : 000001E43D9EA48E // 
- stack : 0000004D0AAFD530 (address in stack) | 000001E43D9E5320 (value in stack)  // 
```


<u>RCX in dump</u>:

![](/assets/img/Pasted image 20250603144559.png)


`r9` address in dump:

![](/assets/img/Pasted image 20250603144822.png)

	- From stack


In dump:

![](/assets/img/Pasted image 20250603144839.png)


### `5)` After every `call` for `CONTEXT` structure creation, it will show the starting address for the created structure:

```c
1) [CONTEXT CtxThread] rax == 0000004D0AAFD5A0
2) [CONTEXT RopProtRW] rax == 0000004D0AAFDA70
3) [CONTEXT RopMemEnc] rax == 0000004D0AAFE410
4) [CONTEXT RopDelay] rax == 0000004D0AAFE8E0
5) [CONTEXT RopMemDec] rax == 0000004D0AAFEDB0
6) [CONTEXT RopProtRX] rax == 0000004D0AAFDF40
7) [CONTEXT RopSetEvt] rax == 0000004D0AAFF280
```


***Interval for each memory address***: `0x4d0` from `CtxThread` -> `RopProtRW` and so on... plus all of them are nulled.

How it looks in dump:

![](/assets/img/Pasted image 20250603145639.png)


### `6)` Some other local variables:

```c
...
    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer   = NULL;
    HANDLE  hEvent      = NULL;
    PVOID   ImageBase   = NULL;
    DWORD   ImageSize   = 0;
    DWORD   OldProtect  = 0;
...
```

![](/assets/img/Pasted image 20250603150431.png)

	- nop dword ptr ... does no operation


### `7)` `rand_s()` function and `rcx` parameter value:

```c
00007FF6DA6810D0  | 48:8D8D 68210000         | lea rcx,qword ptr ss:[rbp+2168]        |
00007FF6DA6810D7  | E8 EC3A0000              | call ekko.7FF6DA684BC8                 | rand_s() function for key generation
```

![](/assets/img/Pasted image 20250603150557.png)


### `8)` Moving onto the `if()` statement scope:

```c
    // Can be randomly generated
    //CHAR    KeyBuf[ 16 ]= { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
	
	CHAR KeyBuf[16];
	unsigned int r = 0;
	for (int i = 0; i < 16; i++) {
		rand_s(&r);
		KeyBuf[i] = (CHAR) r;
	}
	
    USTRING Key         = { 0 };
    USTRING Img         = { 0 };

    PVOID   NtContinue  = NULL;
    PVOID   SysFunc032  = NULL;
```


Iteration comparison:

```c
00007FF6DA6810E7  | 48:FFC3                  | inc rbx                                | rbx:&"C:\\Users\\Cj\\Documents\\shared\\Ekko.exe"
00007FF6DA6810EA  | 48:83FB 10               | cmp rbx,10                             | if() statement
00007FF6DA6810EE  | 7C E0                    | jl ekko.7FF6DA6810D0                   | jump for if() statement
```

	- 0x10 == 16 bytes in decimmal
	- rbx == 'i' variable in this case


### `9)` Extracting the key generated:

![](/assets/img/Pasted image 20250603151053.png)


#### Key generated in dump:

```c
[rsp+rbx+60] == 4D 0AAF D590 // assuming rbx == 0 to get the starting address
```

![](/assets/img/Pasted image 20250603151237.png)

```c
0000004D0AAFD590  50 E7 71 72 C3 B7 96 87 11 37 C6 A1 DD 68 5A 38  PçqrÃ·...7Æ¡ÝhZ8  
```



### `10)` Execution of **`CreateEventW()`**, **`CreateTimerQueue()`**, **`GetProcAddress()`** , **`GetModuleHandleA()`** , **`LoadLibraryA`**,and **`OptionalHeader.SizeOfImage`**:

```c
    hEvent      = CreateEventW( 0, 0, 0, 0 );
    hTimerQueue = CreateTimerQueue();

    NtContinue  = GetProcAddress( GetModuleHandleA( "Ntdll" ), "NtContinue" );
    SysFunc032  = GetProcAddress( LoadLibraryA( "Advapi32" ),  "SystemFunction032" );

    ImageBase   = GetModuleHandleA( NULL );
    ImageSize   = ( ( PIMAGE_NT_HEADERS ) ( (DWORD64) ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew ) )->OptionalHeader.SizeOfImage;
```


<u>CreateEventW</u>:

![](/assets/img/Pasted image 20250603151700.png)


<u>CreateTimerQueue</u>: This doesn't have an argument

<u>GetModuleHandleA</u>:

![](/assets/img/Pasted image 20250603151843.png)

![](/assets/img/Pasted image 20250603151855.png)


<u>GetProcAddress</u>:

- The argument above is also included.

![](/assets/img/Pasted image 20250603152012.png)

![](/assets/img/Pasted image 20250603152031.png)


<u>GetProc plus LoadLibraryA</u>:

![](/assets/img/Pasted image 20250603152134.png)

![](/assets/img/Pasted image 20250603152122.png)


2nd `GetProcAddress`:

![](/assets/img/Pasted image 20250603152202.png)

![](/assets/img/Pasted image 20250603152221.png)

	- 1st param: address to advapi32 pointing to the starting address of SystemFunction032
	- 2nd param: method name inside advapi32 of interest


<u>Another GetModuleHandleA for the ImageBase</u>:

![](/assets/img/Pasted image 20250603152413.png)

![](/assets/img/Pasted image 20250603152342.png)

	- Parameter is NULL
	- Output address for ImageBase: 00007FF6DA680000

![](/assets/img/Pasted image 20250603152641.png)


<u>ImageSize</u>: `( ( PIMAGE_NT_HEADERS ) ( (DWORD64) ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew ) )->OptionalHeader.SizeOfImage;`

![](/assets/img/Pasted image 20250603153200.png)

	- Still zeroed out in stack.


- Moving onto the 

```c
    Key.Buffer  = KeyBuf;
    Key.Length  = Key.MaximumLength = 16;

    Img.Buffer  = ImageBase;
    Img.Length  = Img.MaximumLength = ImageSize;
```

Key Generated reminder:

```c
0000004D0AAFD590  50 E7 71 72 C3 B7 96 87 11 37 C6 A1 DD 68 5A 38  PçqrÃ·...7Æ¡ÝhZ8  
```

Local variables in stack:

![](/assets/img/Pasted image 20250603154608.png)

From Disassembly:

![](/assets/img/Pasted image 20250603154626.png)

	- Use in conjunction with the image above.



<u>Setting up the arguments to `CreateTimerQueueTimer`</u>:

```c
- rcx == 0000004D0AAFF7A8
- rdx == 000001E43D9EBE80
- r8 == 00007FFE7D534E40 (address to kernel32.RtlCaptureContext)
- r9 == 0000004D0AAFD5A0
- stack [rsp+20] == 0
- stack [rsp+28] == 0x20
```

	- WT_EXECUTEINTIMERTHREAD == 0x20


![](/assets/img/Pasted image 20250603175422.png)

	- CreateTimerQueueTimer has output of 0x1


```c
    if ( CreateTimerQueueTimer( &hNewTimer, hTimerQueue, RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD ) )
    {
        WaitForSingleObject( hEvent, 0x32 );

        memcpy( &RopProtRW, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopMemEnc, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopDelay,  &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopMemDec, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopProtRX, &CtxThread, sizeof( CONTEXT ) );
        memcpy( &RopSetEvt, &CtxThread, sizeof( CONTEXT ) );

```


- `WaitForSingleObject`:

```c
- rcx == handle to hEvent == 0xC4
- rdx == 0x32
```

![](/assets/img/Pasted image 20250603175757.png)


- Populating each of the `CONTEXT` data structures:

```c
1) [CONTEXT CtxThread] rax == 0000004D0AAFD5A0
2) [CONTEXT RopProtRW] rax == 0000004D0AAFDA70
3) [CONTEXT RopMemEnc] rax == 0000004D0AAFE410
4) [CONTEXT RopDelay] rax == 0000004D0AAFE8E0
5) [CONTEXT RopMemDec] rax == 0000004D0AAFEDB0
6) [CONTEXT RopProtRX] rax == 0000004D0AAFDF40
7) [CONTEXT RopSetEvt] rax == 0000004D0AAFF280
```


***`RopProtRW`***: `memcpy( &RopProtRW, &CtxThread, sizeof( CONTEXT ) );`

![](/assets/img/Pasted image 20250603180311.png)


Prior to population of ***`RopProtRW`***:

![](/assets/img/Pasted image 20250603180358.png)


These blocks are for `memcpy()`:

![](/assets/img/Pasted image 20250603181114.png)

	- r8 holds the iteration for this. Memcpy() was executed 6 times.


- Populating the `VirtualProtect` structure:

```c
		// VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
        RopProtRW.Rsp  -= 8; // 00007FF6DA68150E  | 48:83C2 F8               | add rdx,FFFFFFFFFFFFFFF8  |
					        // 00007FF6DA68151C  | 48:8995 D8040000         | mov qword ptr ss:[rbp+4D8],rdx         |
					        // ss:[rbp+4D8] == RopProtRW.Rsp
        RopProtRW.Rip   = VirtualProtect; // 00007FF6DA68157B  | 48:8985 38050000         | mov qword ptr ss:[rbp+538],rax                |
        RopProtRW.Rcx   = ImageBase; // 00007FF6DA681512  | 48:89BD C0040000         | mov qword ptr ss:[rbp+4C0],rdi         |
        RopProtRW.Rdx   = ImageSize; // 0x23000 == 143,360 bytes ==> ss:[rbp+4C8] // not sure if this is the actual size...
        RopProtRW.R8    = PAGE_READWRITE; // 00007FF6DA681527  | 48:C785 F8040000 0400000 | mov qword ptr ss:[rbp+4F8],4                 |
        RopProtRW.R9    = &OldProtect; // 
```

	- This are stored in stack.


Here's the block:

![](/assets/img/Pasted image 20250603181653.png)


***`RopProtRW.Rsp  -= 8`***: `ss:[rbp+4d8]`

![](/assets/img/Pasted image 20250603182921.png)


***ImageBase***: `ss:[rbp+4C0] == 4D 0AAF DAF0`

![](/assets/img/Pasted image 20250603181904.png)

![](/assets/img/Pasted image 20250603182213.png)


***`RopProtRW.Rdx`***: `ss:[rbp+4F8]`

![](/assets/img/Pasted image 20250603183122.png)


***`RopProtRW.Rdx = ImageSize;`***: `ss:[rbp+4C8]`

![](/assets/img/Pasted image 20250603184719.png)

	- 0x23000 == 143,360 bytes


***Quick Pause***: Notice the offset to `rbp`? The closer they are to each other, the easier to assume they belong to the same data structure which in this case is `RopProtRW`.

![](/assets/img/Pasted image 20250603184540.png)


***`RopProtRW.Rip = VirtualProtect;`***: `ss:[rbp+538]`


```c
		// "RtlEncryptDecryptRC4"
        // SystemFunction032( &Key, &Img );
        RopMemEnc.Rsp  -= 8;
        RopMemEnc.Rip   = SysFunc032; // 00007FF6DA681541  | 4C:89A5 D80E0000         | mov qword ptr ss:[rbp+ED8],r12                     |
        RopMemEnc.Rcx   = &Img;
        RopMemEnc.Rdx   = &Key;
```

Setting ***`RopMemEnc.Rip`***:

![](/assets/img/Pasted image 20250603183537.png)


- And so on....

```c
        // WaitForSingleObject( hTargetHdl, SleepTime );
        RopDelay.Rsp   -= 8;
        RopDelay.Rip    = WaitForSingleObject;
        RopDelay.Rcx    = NtCurrentProcess();
        RopDelay.Rdx    = SleepTime;

        // SystemFunction032( &Key, &Img );
        RopMemDec.Rsp  -= 8;
        RopMemDec.Rip   = SysFunc032;
        RopMemDec.Rcx   = &Img;
        RopMemDec.Rdx   = &Key;

        // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
        RopProtRX.Rsp  -= 8;
        RopProtRX.Rip   = VirtualProtect;
        RopProtRX.Rcx   = ImageBase;
        RopProtRX.Rdx   = ImageSize;
        RopProtRX.R8    = PAGE_EXECUTE_READWRITE;
        RopProtRX.R9    = &OldProtect;

        // SetEvent( hEvent );
        RopSetEvt.Rsp  -= 8;
        RopSetEvt.Rip   = SetEvent;
        RopSetEvt.Rcx   = hEvent;

        puts( "[INFO] Queue timers" );

```


### 11. Moving onto ***`CreateTimerQueueTimer`***:

```c
        CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD );
        CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD );
        CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD );
        CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD );
        CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD );
        CreateTimerQueueTimer( &hNewTimer, hTimerQueue, NtContinue, &RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD );
```


<u>In assembly form</u>:

![](/assets/img/Pasted image 20250603185442.png)


##### First ***`CreateTimerQueueTimer`*** function call:

![](/assets/img/Pasted image 20250603190357.png)


```c
- rcx == 0000004D0AAFF7A8 // reference to hNewTimer
- rdx == 000001E43D9EBE80 // pointer to hTimerQueue
- r8 == 00007FFE7D6AD900 (ntdll.ZwContinue) // Callback
- r9 == 4D0AAFDA70 // Reference to 'RopProtRW' CONTEXT structure
- stack [rsp+28] == 0000004D0AAFD530 (stack addr) | 00007FF6DA69D040 (stack value) | ekko.00007FF6DA69D040 // DueTime
- stack [rsp+20] == 0000004D0AAFD550 (stack addr) | 000001E400000064 (stack value) // Period
- stack [rsp+30] == 0000004D0AAFD560 (stack addr) | 0000000000000020 (stack value)  // Flags
```

	- stack [rsp+20] -> 0x64 == 100 ms
	- stack [rsp+28] -> 0x0  // There isn't a DueTime - no delay after the signal has been fired.
	- stack [rsp+30] -> 0x20 // WT_EXECUTEINTIMERTHREAD should have an expected value of 0x20.


Sequence of arguments from the stack pointer (`0x0000004D0AAFD530`):

![](/assets/img/Pasted image 20250603191240.png)


- Going through the ***`RopProtRW`*** structure:

```c
"Structure":
// VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
RopProtRW.Rsp  -= 8; // 00007FF6DA68150E  | 48:83C2 F8               | add rdx,FFFFFFFFFFFFFFF8  |
					 // 00007FF6DA68151C  | 48:8995 D8040000         | mov qword ptr ss:[rbp+4D8],rdx         |
					 // ss:[rbp+4D8] == RopProtRW.Rsp
RopProtRW.Rip   = VirtualProtect; // 00007FF6DA68157B  | 48:8985 38050000         | mov qword ptr ss:[rbp+538],rax                |
RopProtRW.Rcx   = ImageBase; // 00007FF6DA681512  | 48:89BD C0040000         | mov qword ptr ss:[rbp+4C0],rdi         |
RopProtRW.Rdx   = ImageSize; // 0x23000 == 143,360 bytes ==> ss:[rbp+4C8] // not sure if this is the actual size...
RopProtRW.R8    = PAGE_READWRITE; // 00007FF6DA681527  | 48:C785 F8040000 0400000 | mov qword ptr ss:[rbp+4F8],4                 |
RopProtRW.R9    = &OldProtect; 
```



<u>Confirmation</u>: ***Refer to the structure of `_CONTEXT`***

- `RopProtRW + 0x80` points to ***RCX***:

![](/assets/img/Pasted image 20250619082323.png)


- Make sure to use the `_CONTEXT` structure as template for the offsets:

```c
RopProtRW.rcx == 0x7ff78a950000  // Image base address
RopProtRW.rdx == 0x00023000      // Image size
RopProtRW.rsp == 0x4fdc0ff878    // stack pointer
RopProtRW.r8 == 0x04             // PAGE_READWRITE -> Memory section's Flag
RopProtRW.r9 == 0x4fdbcff910     // address to old protection
RopProtRW.rip == 0x7ffaacd4c3f0  // Starting address to VirtualProtect()
```


![](/assets/img/Pasted image 20250619083513.png)


***`_CONTEXT`*** in dump:

![](/assets/img/Pasted image 20250619084316.png)



***`RopProtRW.Rip`*** seems to follow to `VirtualProtect` API:

![](/assets/img/Pasted image 20250603193212.png)


The rest of the code:

```c
        puts( "[INFO] Wait for hEvent" );

        WaitForSingleObject( hEvent, INFINITE );

        puts( "[INFO] Finished waiting for event" );
    }

    DeleteTimerQueue( hTimerQueue );
}
```

# Conclusion

Since this Ekko technique relies so much on the WinAPI CreateTimerQueue() along with VirtualProtect() and CreateTimerQueueTimer(), usage of these functions in the same process given their sequence of execution could be flagged as suspicious if not outright malicious and calls for an investigation from the Blue Team.


# Reference

- VX-Underground
- Sektor7