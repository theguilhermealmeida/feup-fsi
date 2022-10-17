# Week 4: SEED Labs – Environment Variable and Set-UID Program Lab 

## Lab Tasks

### Task 1: Manipulating Environment Variables
> In this tasks we had to understand the funcionalities of some commands that can be used to set and unset environment variables.
> * <strong>*printenv*</strong> - prints all the environment variables
> * <strong>*printenv [environment variable name]* </strong> - print a specific environment variable 
> * <strong>*export [new variable name]*</strong> - adds a new environment variable
> * <strong>*unset [variable name]*</strong> - unsets a specific variable

### Task 2: Passing Environment Variables from Parent Process to Child Process

> In task 2 we had to study how a child process gets its environment variables from its parents.  

> First we compiled and executed myprintenv.c to save the environment variables of the child process.  
> We executed the program a second time to check the environment variables of the parent process.  

> Using the *diff* command we observed that the environment variables of the two processes were identical, therefore the child process inherits the parent variables.


### Task 3: Environment Variables and execve()

> In this task we had to study how environment variables are affected when a new program is executed via *execve()*.  

> By executing the given program the first time there were no environment variables.   
> When executing the second time, changing the last parameter of *execve()*, there were environment variables assigned.  

> We can conclude that the new program get its environment variables through the third parameter of *execve()*, which is an array of pointers to strings, were the variables are passed.

### Task 4: Environment Variables and system()

> In task 4, we study how environment variables are affected when a new program is executed via the *system()* function.  
> Unlike *execve()*, *system()* executes */bin/sh* and asks the shell to execute the command.

> We executed the given program and observed that when the *system()* function is called, it doesn't execute the command directly but calls the shell instead. The shell then internily calls the *execve()* command and the environmet variables of the calling process are passed to the to the shell who then passes it to the *execve()* command.

### Task 5: Environment Variable and Set-UID Programs

> Our task was to understand how Set-UID programs and its environment variables are affected.  

> After running the program a first time we changed the ownership of the program to root and made it a Set-UID program.  
> Then using the export command we changed the PATH and LD_LIBRARY_PATH variables and created a new one.  

> After running the program the second time we observed that unlike the other two variables, LD_LIBRARY_PATH did not get into the Set-UID child process.

### Task 6: The PATH Environment Variable and Set-UID Programs

> In task 6 we have to prove that we can get the given Set_UID program to run our own malicious code instead of '/bin/ls'.  

> The program calls the *system()* function to execute '/bin/ls', therefore we created a file with our malicous code called 'ls.c'. The target is to when the 'ls' is written in the shell, our code is executed. 

> To achieve this first we have to change the ownership of our program to root and make it a Set-UID program. 
> Secondly we have to change the PATH environment variable to our current directory followed by the PATH variable.  
> Now if we type 'ls' in the shell our code is executed.

> We observed that the PATH environment variable looks to our 'ls' command in the current directory first, thus running our code instead of the shell's 'ls' command.  
> With this we can prove that the Set-UID program is running our malicous code with root privileges when the PATH environment variable is altered.