# block-ctf
My attempt at doing the block ctf challenges.

## Challenges

1. Sizer Cipher:

The main thing I found out in this was that the key space was 64 characters. After playing arround it I found out that when you query }} to the oracle, you get a reply back 0fff. That gave me a hint that when I have to decipher it in blocks of 3.
Also it helped knowing that the answer is going to be of format flag{ which gave a good headstart to confirm this theory. Then it was only a matter of time. Final answer is in sizer-cipher.txt

2. Where's my key?

This was probably the simplest challenge. After looking at the server code, I spotted two main mistakes:

```py
request = json.loads(self.request.recv(1024))
client_pub = bytes.fromhex(request.get("client_pub", ""))
if len(client_pub) != X25519_KEY_SIZE:
    return

server_priv = os.urandom(X25519_KEY_SIZE)
server_pub = x25519.scalar_base_mult(server_priv)
secret = x25519.scalar_mult(server_priv, client_pub)

response = {"server_pub": server_pub.hex()}

iv = os.urandom(16)
cipher = Cipher(algorithms.AES(secret), modes.CTR(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(FLAG.encode()) + encryptor.finalize()

data = {"iv": iv.hex(), "ct": ct.hex()}

# This is how you combine dictionaries... right?
response = response and data
```

When you do and for two dictionary it only returns the second part of it. Therefore, response is always going to be data. If you also noticec, the secret is calculated by doing scalar matrix multiplcation with client pub and server private. I just passed my client pub to be 0*32 and got the reply. Then we can straight up decipher it.

3. Glitch in crypt:

This one was a bit tricky as I had forgotten my crypto math. I had to take some assitance from ai and look at my notes to confirm my hypothesis. I send a known message to a server that has a faulty RSA implementation, and due to its fault, I get back a corrupted decryption. By comparing my original message with the faulty decryption, I can calculate the difference which helps me factor the RSA modulus (n) into its prime components (p and q).

Once I have p and q, I can compute the private key (d), which I then use to decrypt the actual flag they sent me.

4. nothing-but-stringz:

This was a llvm given file which I had to reverse engineer. I just did llvm nothin_but_stringz.o and got the flag.

5. Echo: 

This was a simple buffer overflow challenge where the program uses gets which does not do bounds checking which makes overwriting the return address trivial. My exploitation strategy was to fill the 256 byte buffer, account 8 bytes for rbp and then overwrite the return address with the address of `print_flag`. 

6. Only Ws: 

This challenge had seccomp restrictions allowing us to only use `exit` and `write` syscalls. The program outputs flag's address, so my exploitation strategy was to recv the provided address and then use write syscall to print out the flag onto the screen (write(1, flag_address, 100))

7. Echo 2:

This challenge has a stack canary protection to protect overwriting return address, however, on further examination, I noticed that the the code prints out the buffer content using `print(echo_buffer)` hinting towards a format string vulnerability. In the first payload, I leaked the canary value using the fmtstr vulnerbaility and then created a second payload to fill the buffer, then insert the leaked canary value, 8 bytes for RBP and then substituted print_flag's address to the return address. 

Acknowledgment: Aishwarya Tapade for being my teammate during this ctf. We learnt a lot!
