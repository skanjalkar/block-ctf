import socket
import math
from Crypto.Util.number import inverse, long_to_bytes
import re

n = 30392456691103520456566703629789883376981975074658985351907533566054217142999128759248328829870869523368987496991637114688552687369186479700671810414151842146871044878391976165906497019158806633675101
e = 65537

m = 42
c = pow(m, e, n)
c_hex = hex(c)[2:]  # Remove '0x' prefix

HOST = '54.85.45.101'
PORT = 8010

def send_ciphertext_get_plaintext(c_hex):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = ''
        while 'Send your ciphertext in hex format:' not in data:
            part = s.recv(4096).decode()
            if not part:
                break
            data += part
        s.sendall((c_hex + '\n').encode())
        response = ''
        while True:
            part = s.recv(4096).decode()
            if not part:
                break
            response += part
            if any(keyword in response for keyword in ['Decrypted message', 'Invalid', 'Note:', 'Ciphertext must be less than modulus n.', 'Goodbye!']):
                break
        faulty = 'Note: Fault occurred during decryption.' in response
        m_prime = None
        for line in response.strip().split('\n'):
            if 'Decrypted message (hex):' in line:
                m_prime_hex = line.split(':', 1)[1].strip()
                m_prime = int(m_prime_hex, 16)
                break
        return m_prime, faulty

def get_encrypted_flag():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = ''
        while 'Send your ciphertext in hex format:' not in data:
            part = s.recv(4096).decode()
            if not part:
                break
            data += part
        s.sendall(('flag\n').encode())
        response = ''
        while True:
            part = s.recv(4096).decode()
            if not part:
                break
            response += part
            if 'Encrypted flag (hex):' in response and 'Flag length (bytes):' in response:
                break
        ciphertext_hex = None
        flag_length = None
        for line in response.strip().split('\n'):
            if 'Encrypted flag (hex):' in line:
                ciphertext_hex = line.split(':', 1)[1].strip().replace('0x', '')
            if 'Flag length (bytes):' in line:
                flag_length = int(line.split(':', 1)[1].strip())
        if ciphertext_hex is None or flag_length is None:
            print("Failed to retrieve encrypted flag.")
            exit()
        ciphertext = int(ciphertext_hex, 16)
        return ciphertext, flag_length

print("Attempting to obtain a faulty decryption...")
attempts = 0
while True:
    m_prime, faulty = send_ciphertext_get_plaintext(c_hex)
    attempts += 1
    if m_prime is None:
        continue
    if faulty:
        print(f"m' (faulty plaintext) = {m_prime}")
        break
    else:
        print(f"No fault detected on attempt {attempts}. Retrying...")

delta = (m - m_prime) % n
print(f"Computed delta = m - m' mod n = {delta}")
q = math.gcd(delta, n)
if 1 < q < n and n % q == 0:
    print(f"Recovered q: {q}")
    p = n // q
    print(f"Recovered p: {p}")
else:
    print("Failed to recover prime factors.")
    exit()

phi_n = (p - 1) * (q - 1)
d = inverse(e, phi_n)
print("Computed private key d.")

# test_ciphertext = pow(m, e, n)
# test_decrypted = pow(test_ciphertext, d, n)
# if test_decrypted == m:
#     print("Test decryption successful.")
# else:
#     print("Test decryption failed. Private key may be incorrect.")
#     exit()

ciphertext, flag_length = get_encrypted_flag()
print(f"Encrypted flag (hex): {hex(ciphertext)}")
print(f"Flag length (bytes): {flag_length}")

n_bit_length = n.bit_length()
flag_bit_length = flag_length * 8
# print(f"Modulus n bit length: {n_bit_length} bits")
# print(f"Flag bit length: {flag_bit_length} bits")

if flag_bit_length >= n_bit_length:
    print("Flag is larger than modulus n. Cannot recover original flag from decrypted value.")
    exit()

flag_int = pow(ciphertext, d, n)
flag_bytes = long_to_bytes(flag_int)

if len(flag_bytes) < flag_length:
    flag_bytes = b'\x00' * (flag_length - len(flag_bytes)) + flag_bytes

# print(f"Length of decrypted bytes: {len(flag_bytes)}")
# print(f"Decrypted bytes (hex): {flag_bytes.hex()}")

# Search for the flag pattern thanks chatgpt
match = re.search(b'flag\{.*?\}', flag_bytes)
if match:
    flag = match.group().decode('utf-8')
    print(f"Decrypted Flag: {flag}")
else:
    # Try reversing bytes
    flag_bytes_reversed = flag_bytes[::-1]
    match_reversed = re.search(b'flag\{.*?\}', flag_bytes_reversed)
    if match_reversed:
        flag = match_reversed.group().decode('utf-8')
        print(f"Decrypted Flag (reversed bytes): {flag}")
    else:
        # Print decrypted bytes in readable format
        print("Decrypted bytes (ASCII):")
        print(flag_bytes.decode('utf-8', errors='replace'))
        print("Could not find flag pattern in decrypted bytes.")
