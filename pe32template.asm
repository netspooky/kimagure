BITS 32
;--- PE32 Blank Header for shellcode ---------------------------------------\\--
; I based this off of the PE I made for https://n0.lol/a/pemangle.html
; You could assemble this as is like 
;   nasm -f bin pe32template.asm -o template.exe
; Then take a raw file with shellcode in it and do
;   cat shellcode.bin >> template.exe
;
; /!\ Note that if you run this on a 64 bit Windows, it needs to be lined up to
;     268 bytes. You can add a bunch of junk to the end if you like, like a 
;     bunch of zeroes. Also you might get a 0xc0000005 error when you run it
;     on 64 bit Windows. This is fine but we should prolly test more extensively
;     on other versions just to track what runs it fine and what doesn't.
; 
; These are the headers just for reference
;┌─ DOS Header ───────────────────┐ ┌─ PE Header ──────────────────────────────┐
;│ #  │ Sz │ Desc                 │ │ #  │ Sz │ Desc                           │
;├────┼────┼──────────────────────┤ ├────┼────┼────────────────────────────────┤
;│ MA │ 2  │ e_magic              │ │ PA │ 4  │ PE Signature                   │
;│ MB │ 2  │ e_cblp **            │ │ PB │ 2  │ Machine (Intel 386)            │
;│ MC │ 2  │ e_cp **              │ │ PC │ 2  │ NumberOfSections               │
;│ MD │ 2  │ e_crlc **            │ │ PD │ 4  │ TimeDateStamp **               │
;│ ME │ 2  │ e_cparhdr **         │ │ PE │ 4  │ PointerToSymbolTable **        │
;│ MF │ 2  │ e_minalloc **        │ │ PF │ 4  │ NumberOfSymbols **             │
;│ MG │ 2  │ e_maxalloc **        │ │ PG │ 2  │ SizeOfOptionalHeader           │
;│ MH │ 2  │ e_ss **              │ │ PH │ 2  │ Characteristics (no relocs,    │
;│ MI │ 2  │ e_sp **              │ │    │    │ executable, 32 bit)            │
;│ MJ │ 2  │ e_csum **            │ └──────────────────────────────────────────┘
;│ MK │ 2  │ e_ip **              │ ┌─ Optional Header ────────────────────────┐
;│ ML │ 2  │ e_cs **              │ │ #  │ Sz │ Desc                           │
;│ MM │ 2  │ e_lsarlc **          │ ├────┼────┼────────────────────────────────┤
;│ MN │ 2  │ e_ovno **            │ │ OA │ 2  │ Magic (PE32)                   │
;│ MO │ 8  │ e_res **             │ │ OB │ 1  │ MajorLinkerVersion **          │
;│ MP │ 2  │ e_oemid **           │ │ OC │ 1  │ MinorLinkerVersion **          │
;│ MQ │ 2  │ e_oeminfo **         │ │ OD │ 4  │ SizeOfCode **                  │
;│ MR │ 20 │ e_res2 **            │ │ OE │ 4  │ SizeOfInitializedData **       │
;│ MS │ 4  │ e_lfanew PE Sig Addr │ │ OF │ 4  │ SizeOfUninitializedData **     │
;└────────────────────────────────┘ │ OG │ 4  │ AddressOfEntryPoint            │
;                                   │ OH │ 4  │ BaseOfCode **                  │
; Anything marked with a * means    │ OI │ 4  │ BaseOfData **                  │
; that it is unused. Some of these  │ OJ │ 4  │ ImageBase                      │
; might have some expected value    │ OK │ 4  │ SectionAlignment               │
; ranges to respect, so keep that   │ OL │ 4  │ FileAlignment                  │
; in mind when playing with them!   │ OM │ 2  │ MajorOperatingSystemVersion ** │
;                                   │ ON │ 2  │ MinorOperatingSystemVersion ** │
;                                   │ OO │ 2  │ MajorImageVersion **           │
;                                   │ OP │ 2  │ MinorImageVersion **           │
;                                   │ OQ │ 2  │ MajorSubsystemVersion          │
;                                   │ OR │ 2  │ MinorSubsystemVersion **       │
;                                   │ OS │ 4  │ Win32VersionValue **           │
;                                   │ OT │ 4  │ SizeOfImage                    │
;                                   │ OU │ 4  │ SizeOfHeaders                  │
;                                   │ OV │ 4  │ CheckSum ** *                  │
;                                   │ OW │ 2  │ Subsystem (Win32 GUI)          │
;                                   │ OX │ 2  │ DllCharacteristics **          │
;                                   │ OY │ 4  │ SizeOfStackReserve **          │
;                                   │ OZ │ 4  │ SizeOfStackCommit              │
;                                   │ O1 │ 4  │ SizeOfHeapReserve              │
;                                   │ O2 │ 4  │ SizeOfHeapCommit **            │
;                                   │ O3 │ 4  │ LoaderFlags **                 │
;                                   │ O4 │ 4  │ NumberOfRvaAndSizes **         │
;                                   └──────────────────────────────────────────┘
; This is our empty template annotated ─────────────────────────────────────────
;  $ nasm -f bin pe32template.asm -o pe32template.bin
;  $ sha256sum pe32template.bin
;  49c684162277f8140663f871060aa7827599fdd252070b406e5c2c3492e779a3
;  $ xxd pe32template.bin
;                      MC── MD── ME── MF── MG── MH──
;            MA── MB── PA─────── PB── PC── PD───────
;  00000000: 4d5a 0001 5045 0000 4c01 0000 0000 0000  MZ..PE..L.......
;            MI── MJ── MK── ML── MM── MN── MO───────
;            PE─────── PF─────── PG── PH── OA── OBOC
;  00000010: 0000 0000 0000 0000 6000 0301 0b01 0000  ........`.......
;            MO─────── MP── MQ── MR─────────────────
;            OD─────── OE─────── OF─────── OG───────
;  00000020: 0000 0000 0000 0000 0000 0000 7c00 0000  ............|...
;            MR─────────────────────────── MS───────
;            OH─────── OI─────── OJ─────── OK───────
;  00000030: 0000 0000 0000 0000 0000 4000 0400 0000  ..........@.....
;            OL─────── OM── ON── OO── OP── OQ── OR──
;  00000040: 0400 0000 0000 0000 0000 0000 0500 0000  ................
;            OS─────── OT─────── OU─────── OV───────
;  00000050: 0000 0000 8000 0000 7c00 0000 0000 0000  ........|.......
;            OW── OX── OY─────── OZ─────── O1───────
;  00000060: 0200 0004 0000 1000 0010 0000 0000 1000  ................
;            O2─────── O3─────── O4───────          
;  00000070: 0000 0000 0000 0000 0000 0000            ............
;
mzhdr: ; MZ Header ──┬───────────┬──────────────────────────────────────────────
  dw "MZ"     ; 0x00 │ 4d5a      │ [MA] e_magic
  dw 0x100    ; 0x02 │ 0001      │ [MB] e_cblp This value will bypass TinyPE detections!
pehdr: ; PE Header ──┼───────────┼──────────────────────────────────────────────
  dd "PE"     ; 0x04 │ 5045 0000 │ [MC] e_cp [MD] e_crlc [PA] PE Signature
  dw 0x014C   ; 0x08 │ 4c01      │ [ME] e_cparhdr [PB] Machine (Intel 386)
  dw 0        ; 0x0A │ 0000      │ [MF] e_minalloc [PC] NumberOfSections (0 haha)
  dd 0        ; 0x0C │ 0000 0000 │ [MG] e_maxalloc [MH] e_ss [PD] TimeDateStamp 
  dd 0        ; 0x10 │ 0000 0000 │ [MI] e_sp [MJ] e_csum [PE] PointerToSymbolTable
  dd 0        ; 0x14 │ 0000 0000 │ [MK] e_ip [ML] e_cs [PF] NumberOfSymbols 
  dw 0x60     ; 0x18 │ 6000      │ [MM] e_lsarlc [PG] SizeOfOptionalHeader
  dw 0x103    ; 0x1A │ 0301      │ [MN] e_ovno [PH] Characteristics
ophdr: ; Optional Header ────────┼───────────────────────────────────────────────
  dw 0x10B    ; 0x1C │ 0b01      │ [MO] e_res [OA] Magic (PE32)
  dw 0        ; 0x1E │ 0000      │ [MO] e_res [OB] MajorLinkerVersion [OC] MinorLinkerVersion
  dd 0        ; 0x20 │ 0000 0000 │ [MO] e_res [OD] SizeOfCode
  dd 0        ; 0x24 │ 0000 0000 │ [MP] e_oemid [MQ] e_oeminfo [OE] SizeOfInitializedData
  dd 0        ; 0x28 │ 0000 0000 │ [MR] e_res2 [OF] SizeOfUninitializedData
  dd 0x7C     ; 0x2C │ 7c00 0000 │ [MR] e_res2 [OG] AddressOfEntryPoint
  dd 0        ; 0x30 │ 0000 0000 │ [MR] e_res2 [OH] BaseOfCode
  dd 0        ; 0x34 │ 0000 0000 │ [MR] e_res2 [OI] BaseOfData
  dd 0x400000 ; 0x38 │ 0000 4000 │ [MR] e_res2 [OJ] ImageBase
  dd 4        ; 0x3C │ 0400 0000 │ [MS] e_lfanew [OK] SectionAlignment
  dd 4        ; 0x40 │ 0400 0000 │ [OL] FileAlignment
  dd 0        ; 0x44 │ 0000 0000 │ [OM] MajorOperatingSystemVersion [ON] MinorOperatingSystemVersion
  dd 0        ; 0x48 │ 0000 0000 │ [OO] MajorImageVersion [OP] MinorImageVersion
  dd 5        ; 0x4C │ 0500 0000 │ [OQ] MajorSubsystemVersion [OR] MinorSubsystemVersion
  dd 0        ; 0x50 │ 0000 0000 │ [OS] Win32VersionValue
  dd 0x80     ; 0x54 │ 8000 0000 │ [OT] SizeOfImage
  dd 0x7C     ; 0x58 │ 7c00 0000 │ [OU] SizeOfHeaders
  dd 0        ; 0x5C │ 0000 0000 │ [OV] CheckSum
  dw 2        ; 0x60 │ 0200      │ [OW] Subsystem (Win32 GUI)
  dw 0x400    ; 0x62 │ 0004      │ [OX] DllCharacteristics   
  dd 0x100000 ; 0x64 │ 0000 1000 │ [OY] SizeOfStackReserve   
  dd 0x1000   ; 0x68 │ 0010 0000 │ [OZ] SizeOfStackCommit    
  dd 0x100000 ; 0x6C │ 0000 1000 │ [O1] SizeOfHeapReserve    
  dd 0        ; 0x70 │ 0000 0000 │ [O2] SizeOfHeapCommit !! Was 0x100 in an older version
  dd 0        ; 0x74 │ 0000 0000 │ [O3] LoaderFlags 
  dd 0        ; 0x78 │ 0000 0000 │ [O4] NumberOfRvaAndSizes  ; Note - this is touchy 
; All code codes here, the binary already points to entrypoint at 0x7C (in [OG])
; You can uncomment the next line if you need a label to point to this location.
;codesec:      ; 0x7C - Start of code ───────────────────────────────────────────
;                       ; MachineCode ; Description 
;  ret ; Dummy instruction
; You can use this to fill up the binary to pad to 268, just keep it at the end
;times 0x10C - ($ - $$)  db 0 
