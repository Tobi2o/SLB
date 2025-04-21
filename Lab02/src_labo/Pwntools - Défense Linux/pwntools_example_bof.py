from pwn import *
import struct

#Pwntools documentation
# https://docs.pwntools.com/en/stable/#

#starting a process with binary named 'bof'
proc = process('./bof')

input_string = ("ABCD")

#sending 'ABCD' to the process 
proc.sendline(input_string)

#receive lines from process until a line containing 'You entered' is received 
proc.recvuntil('You entered', timeout=10)
#The line of interest is the next line -> receive line from process
line = proc.recvline()
print("line after You Entered: ", line)

#Get the bytes we entered
msg_bytes = line[18:22]
print("bytes: ", msg_bytes)

#Convert bytes to integer
msg_int = struct.unpack("I",msg_bytes)[0]
print("bytes to integer: " ,msg_int)

#Convert integer to hex
msg_int_hex = hex(msg_int)
print("integer to hex: ", msg_int_hex) 

#Convert integer to bytes
msg_bytes = struct.pack("I", msg_int)
print("integer to bytes: ", msg_bytes)

#Convert integer to bytes using little-endian format
msg_bytes_little_endian = struct.pack("<I", msg_int)
print("integer to bytes, little endian: ", msg_bytes_little_endian)

#Convert integer to bytes using big-endian format
msg_bytes_big_endian = struct.pack(">I", msg_int)
print("integer to bytes, big endian: ", msg_bytes_big_endian)
