# Week 5: SEED Labs – Buffer Overflow Attack Lab (Set-UID Version)

## Task 1: Getting Familiar with Shellcode

> In this task we need to launch the Shell by invoking the provided  Shellcode.  
> As expected when executing the call_shellcode.c file we can exploit the buffer overflow vulnerability and conclude that by overfloating the stack we gain control of the shell.


## Task 2 and 3: Understanding the Vulnerable Program

> In this two task our goal is to understand the given vulnerable program and how we can exploit its vulnerability.

> The given program reads an input file and then passes the input to another buffer.  
> The initial input buffer has a maximum length of 517 bytes, but the the second buffer has a size of BUF_SIZE that is currently set to less than 517 bytes.   
> The program uses strcpy() to copy the string to the second buffer, as this function doesn't check boundaries, a buffer overflow error will occur.  
> This program is a root-owned Set-UID program, thus a normal user can exploit thus buffer overflow vulnerability and get a root shell.

## Task 3: Launching Attack on 32-bit Program (Level 1)

> In task 3 we need to exploit the buffer-overflow vulnerability of the given file to gain the root privileg.

> We started by using *gdb* to debug *stack-L1-dbg*, where we obtained the *ebp* and the *buffer's address* values.
```
gdb-peda$ b bof
Breakpoint 1 at 0x122d: file stack.c, line 11.
gdb-peda$ run
...
gdb-peda$ next
...
gdb-peda$ p $ebp
$3 = (void *) 0xffffcf38
gdb-peda$ p &buffer
$4 = (char (*)[100]) 0xffffcecc
``` 
> Then we created a file(*badfile*) to fill with the program given to us. In that program we had to define some variables in order to write what we wanted in the file.
```
start = 517-len(shellcode)
...
ret    = ebp+199 #could be any number between 120 and 199
offset = ebp-buffer + 4
```
> We chose that value for *start* since we knew the buffer had size 517 and we wanted to have the *shellcode* we obtained in Task 1 at the end of that buffer.
> 
> According to the stack frame structure, the return address is 4 bytes after the previous frame pointer(*ebp*) since we are in a 32 bits architecture, so we added 4 to the *ebp* value and removed the value of the buffer initial position, to get the return address position relative to the buffer(*offset*).
>
> The *ret* variable is the value to where the function will go after returning. We knew that for the program to run we would need a value from a specific range. After some research, we observed that any value in the range [120,199] could be used to add to the ebp address value. Using 199 as an example, our *ret* had 0xffffcf93 as value. 

> After saving all variables in exploit.py, we ran it and the *stack-L1* program and observed that our malicious code worked and opened a root shell.