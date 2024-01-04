---
title: "CTF Writeup for World Peace - A challenge in IITB Trust Lab CTF Round 2 2023"
last_modified_at: 2023-10-27
classes: wide
categories:
  - writeups
  - 2k23
  - IITBCTF
tags:
  - Writeup
  - Trust Lab CTF
  - Stack Canary
  - pwn
---

This challenge was created by me for Trust Lab CTF Round 2 held in October 2023

# Challenge Description

In the not-so-distant future, the world has finally achieved a state of unprecedented global harmony. Cats, once believed to be mere pets, have risen to prominence as ambassadors of peace and unity. The world has come to cherish the soothing sound of cats' meows as a symbol of world peace. However, a sinister plot threatens to disrupt this tranquility. Can you help the felines figure out the key to world peace?

[Here]({{site.baseurl}}/assets/ctf/2023/IITBCTF/world_peace) are the challenge files.

## Solution 

```c
0040135b      int32_t size
0040135b      __isoc99_scanf(&data_4020c3, &size)
00401365      meow()
0040136a      int32_t rax_4 = size
00401377      int64_t var_b8 = sx.q(rax_4) - 1
004013b1      int64_t rax_8 = divu.dp.q(0:(sx.q(rax_4) + 0xf), 0x10) * 0x10
❓️004013c8      while (rsp != &var_c8 - (rax_8 & 0xfffffffffffff000))
004013ca          rsp = rsp - 0x1000
004013d1          *(rsp + 0xff8) = *(rsp + 0xff8)
004013e5      void* rsp_1 = rsp - zx.q(rax_8.d & 0xfff)
004013f4      if (zx.q(rax_8.d & 0xfff) != 0)
004013ff          void* rax_11 = zx.q(rax_8.d & 0xfff) - 8 + rsp_1
00401402          *rax_11 = *rax_11
00401423      *(rsp_1 + sx.q(size)) = 0
00401436      printf("Say Something: ")
00401445      fflush(stdout)
00401462      read(0, rsp_1, sx.q(var_bc))
0040146c      meow()
0040147b      puts(rsp_1)
0040148a      fflush(stdout)
00401494      meow()
004014a3      puts("Consuming consumerism: ")
004014b2      fflush(stdout)
004014cb      void var_a8
004014cb      read(0, &var_a8, 0x190)
004014d0      int64_t rax_22 = 0
004014e5      if (rax != *(fsbase + 0x28))
004014e7          rax_22 = __stack_chk_fail()
004014fa      return rax_22
```

We see that the program has stack canary enabled for all the functions.
The last read is of size 0x190 but the buffer at which it is storing is smaller in size.
After 0xa8 bytes, that would overwrite the return address and there is a win function.
Moreover, as the binary is not pie, the address of win function is always same.

Now we need to leak the canary in order to overwrite the return address.
After getting the size of the input from the user, the program allocates a space for the buffer.
The size of this buffer is decided at runtime. This buffer is being stored on stack.
Thus, this buffer contains part of the stack used by other function calls before the allocation. 
`meow` function is called just before buffer allocation, therefore, the buffer contains the canary.
The buffer is being printed as a string. If we fill the buffer till the canary, we can leak the canary.

Using gdb, we can find out that if we allocate 300 bytes of buffer, after entering 280 bytes, the canary is there.
As last byte of canary is null, we need to write 281 bytes in the buffer.
When the buffer is printed, the 7 bytes after 281 bytes are bytes of canary.

```python
p.sendline(b'300')
p.sendline(b'a'*280)
p.recvuntil(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n')
canary = b'\x00' + p.recv(7)
```

Now, we have the canary and we can use it to overwrite the return address and print the flag.
[Here]({{site.baseurl}}/assets/ctf/2023/IITBCTF/world_peace_exploit.py) is the exploit for the challenge.