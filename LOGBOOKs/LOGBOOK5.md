# Week 5: SEED Labs – Buffer Overflow Attack Lab (Set-UID Version)

## Task 1: Getting Familiar with Shellcode

> In this task we need to launch the Shell by invoking the provided  Shellcode.  
> As expected when executing the call_shellcode.c file we can exploit the buffer overflow vulnerability and conclude that by overfloating the stack we gain control of the shell.


## Task 2 and 3: Understanding the Vulnerable Program

> In this two task our goal is to understand the given vulnerable program and how we can exploit its vulnerability.

> The given program reads an input file and then passes the input to another buffer.  
> The initial input buffer has a maximum length of 517 bytes, but the the second buffer has a size of BUF_SIZE that is currently set to less than 517 bytes.   
> The program uses strcpy() to copy the string to the second buffer, as this function doesn't check boundaries, a buffer overflow error will occur.  
> This prgram is a root-owned Set-UID prgram, thus a noram user can exploit thus buffer overflow vulnerability and get a root shell.

## Task 3: Launching Attack on 32-bit Program (Level 1)

> In task 3 we need to exploit the buffer-overflow vulnerability of the given file to gain the root privileg.

>   


