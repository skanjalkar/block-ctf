import os
import x25519
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import binascii

client_pub =  b'\x00' * 32
print('{"client_pub": "' + client_pub.hex() + '"}')
# Convert the provided IV and ciphertext from hex
iv = binascii.unhexlify("9840395f8567fc35ee4c6ad65e179f0b")
ct = binascii.unhexlify("f6b1bcfe633acf644f3881912da2b6f667a4df869b46243cb781402627cdc917084168105b40629e3c3598272597")

cipher = Cipher(algorithms.AES(client_pub), modes.CTR(iv))
decryptor = cipher.decryptor()

pt = decryptor.update(ct) + decryptor.finalize()

print(pt.decode())
