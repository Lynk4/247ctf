# THE MORE THE MERRIER

### Description:

One byte is great. But what if you need more? Can you find the flag hidden in this binary?

---

### basic file check:

---
```bash
❯ checksec --file=the_more_the_merrier
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols	 No	0		0		the_more_the_merrier

```
---

### Executing the binary:

---
```bash
❯ ./the_more_the_merrier
Nothing to see here..
```
---

let's open it in hexeditor:


## hexeditor

```bash
File: the_more_the_merrier                                                                               ASCII Offset: 0x00000731 / 0x00001777 (%31)  M
00000550  E6 00 00 00  FF 15 86 0A   20 00 F4 0F  1F 44 00 00                                                                          ........ ....D..
00000560  48 8D 3D A9  0A 20 00 55   48 8D 05 A1  0A 20 00 48                                                                          H.=.. .UH.... .H
00000570  39 F8 48 89  E5 74 19 48   8B 05 5A 0A  20 00 48 85                                                                          9.H..t.H..Z. .H.
00000580  C0 74 0D 5D  FF E0 66 2E   0F 1F 84 00  00 00 00 00                                                                          .t.]..f.........
00000590  5D C3 0F 1F  40 00 66 2E   0F 1F 84 00  00 00 00 00                                                                          ]...@.f.........
000005A0  48 8D 3D 69  0A 20 00 48   8D 35 62 0A  20 00 55 48                                                                          H.=i. .H.5b. .UH
000005B0  29 FE 48 89  E5 48 C1 FE   03 48 89 F0  48 C1 E8 3F                                                                          ).H..H...H..H..?
000005C0  48 01 C6 48  D1 FE 74 18   48 8B 05 21  0A 20 00 48                                                                          H..H..t.H..!. .H
000005D0  85 C0 74 0C  5D FF E0 66   0F 1F 84 00  00 00 00 00                                                                          ..t.]..f........
000005E0  5D C3 0F 1F  40 00 66 2E   0F 1F 84 00  00 00 00 00                                                                          ]...@.f.........
000005F0  80 3D 19 0A  20 00 00 75   2F 48 83 3D  F7 09 20 00                                                                          .=.. ..u/H.=.. .
00000600  00 55 48 89  E5 74 0C 48   8B 3D FA 09  20 00 E8 0D                                                                          .UH..t.H.=.. ...
00000610  FF FF FF E8  48 FF FF FF   C6 05 F1 09  20 00 01 5D                                                                          ....H....... ..]
00000620  C3 0F 1F 80  00 00 00 00   F3 C3 66 0F  1F 44 00 00                                                                          ..........f..D..
00000630  55 48 89 E5  5D E9 66 FF   FF FF 55 48  89 E5 48 83                                                                          UH..].f...UH..H.
00000640  EC 10 48 8D  05 9F 00 00   00 48 89 45  F8 48 8D 3D                                                                          ..H......H.E.H.=
00000650  38 01 00 00  E8 B7 FE FF   FF B8 00 00  00 00 C9 C3                                                                          8...............
00000660  41 57 41 56  49 89 D7 41   55 41 54 4C  8D 25 46 07                                                                          AWAVI..AUATL.%F.
00000670  20 00 55 48  8D 2D 46 07   20 00 53 41  89 FD 49 89                                                                           .UH.-F. .SA..I.
00000680  F6 4C 29 E5  48 83 EC 08   48 C1 FD 03  E8 57 FE FF                                                                          .L).H...H....W..
00000690  FF 48 85 ED  74 20 31 DB   0F 1F 84 00  00 00 00 00                                                                          .H..t 1.........
000006A0  4C 89 FA 4C  89 F6 44 89   EF 41 FF 14  DC 48 83 C3                                                                          L..L..D..A...H..
000006B0  01 48 39 DD  75 EA 48 83   C4 08 5B 5D  41 5C 41 5D                                                                          .H9.u.H...[]A\A]
000006C0  41 5E 41 5F  C3 90 66 2E   0F 1F 84 00  00 00 00 00                                                                          A^A_..f.........
000006D0  F3 C3 00 00  48 83 EC 08   48 83 C4 08  C3 00 00 00                                                                          ....H...H.......
000006E0  01 00 02 00  00 00 00 00   32 00 00 00  34 00 00 00                                                                          ........2...4...
000006F0  37 00 00 00  43 00 00 00   54 00 00 00  46 00 00 00                                                                          7...C...T...F...
00000700  7B 00 00 00  36 00 00 00   64 00 00 00  66 00 00 00                                                                          {...6...d...f...
00000710  32 00 00 00  31 00 00 00   35 00 00 00  65 00 00 00                                                                          2...1...5...e...
00000720  62 00 00 00  33 00 00 00   63 00 00 00  63 00 00 00                                                                          b...3...c...c...
00000730  37 00 00 00  33 00 00 00   34 00 00 00  30 00 00 00                                                                          7...3...4...0...
00000740  37 00 00 00  32 00 00 00   36 00 00 00  37 00 00 00                                                                          7...2...6...7...
00000750  30 00 00 00  33 00 00 00   31 00 00 00  61 00 00 00                                                                          0...3...1...a...
00000760  31 00 00 00  35 00 00 00   62 00 00 00  30 00 00 00                                                                          1...5...b...0...
00000770  61 00 00 00  62 00 00 00   33 00 00 00  36 00 00 00                                                                          a...b...3...6...
00000780  63 00 00 00  7D 00 00 00   00 00 00 00  4E 6F 74 68                                                                          c...}.......Noth
00000790  69 6E 67 20  74 6F 20 73   65 65 20 68  65 72 65 2E                                                                          ing to see here.
000007A0  2E 00 00 00  01 1B 03 3B   38 00 00 00  06 00 00 00                                                                          .......;8.......
000007B0  5C FD FF FF  84 00 00 00   7C FD FF FF  AC 00 00 00                                                                          \.......|.......
000007C0  8C FD FF FF  54 00 00 00   96 FE FF FF  C4 00 00 00                                                                          ....T...........
000007D0  BC FE FF FF  E4 00 00 00   2C FF FF FF  2C 01 00 00                                                                          ........,...,...
^G Help   ^C Exit (No Save)   ^T goTo Offset   ^X Exit and Save   ^W Search   ^U Undo   ^L Redraw   ^E Text Mode   ^R CharSet   ^P Spacing   F5 Color

```
---

And we find the flag ..buried in it.................

Flag:

```
247CTF{6df215eb3cc73407267031a15b0ab36c}
```

---
