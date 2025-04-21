# https://reverseengineering.stackexchange.com/questions/13928/managing-inputs-for-payload-injection
import sys
sys.stdout.buffer.write(b"\x61"*32+b"BCDEFGHIJKLMNOPQRSTU")
