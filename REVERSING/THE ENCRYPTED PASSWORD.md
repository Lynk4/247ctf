# THE ENCRYPTED PASSWORD

---


Description:

You won't find the admin's secret password in this binary. We even encrypted it with a secure one-time-pad. Can you still recover the password?


---

basic file check:

```bash
❯ file encrypted_password
encrypted_password: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e66644a82644c5ac6ab7a507cc5c6e84432ee0ad, stripped
```
---


```bash
❯ checksec --file=encrypted_password
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols	 No	0		2		encrypted_password


```

---

let's run the binary.........

```bash
❯ ./encrypted_password
Enter the secret password:
idontknow

```

Nothing happens:

let's use ltrace


```bash
❯ ltrace ./encrypted_password
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
puts("Enter the secret password:"Enter the secret password:
)           = 27
fgets(dev
"dev\n", 33, 0x7f1fa70f28e0)           = 0x7ffd5fc2fec0
strcmp("dev\n", "141c85ccfb2ae19d8d8c224c4e403dce"...) = 51
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
strlen("875e9409f9811ba8560beee6fb0c77d2"...) = 32
+++ exited (status 0) +++
❯ ./encrypted_password
Enter the secret password:
141c85ccfb2ae19d8d8c224c4e403dce
You found the flag!
247CTF{141c85ccfb2ae19d8d8c224c4e403dce}

```

---
Its parameters were exposed by the strcmp. Therefore, in order to make the comparison valid, we must utilize the acquired string (142c85ccfb2ae19d8d8c224c4e403dce):

---



