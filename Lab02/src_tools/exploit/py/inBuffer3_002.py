# https://reverseengineering.stackexchange.com/questions/13928/managing-inputs-for-payload-injection
import sys
sys.stdout.buffer.write(b"\x61"*400+b"\x62"*8+b"\x63"*4+b"\xff"*4)
