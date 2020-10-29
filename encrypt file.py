import os

from Crypto.Cipher import AES

key = os.urandom(32)
cipher = AES.new(key, AES.MODE_EAX)
file_out = open("keyf", "wb")
file_out.write(key)
file_out.close()
filename = input("Input File Name: ")
tba = open(filename, "rb")
tbe = tba.read()
tba.close()
data = tbe
ciphertext, tag = cipher.encrypt_and_digest(data)
file_out = open("encryptedf", "wb")
[ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
file_out.close()