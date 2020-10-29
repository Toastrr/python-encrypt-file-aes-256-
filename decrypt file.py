from Crypto.Cipher import AES

file_in = open("encryptedf", "rb")
nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
file_in = open("keyf", "rb")
key = file_in.read()
file_in.close()
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
filename = input("Input File Name: ")
file = open(filename, "wb")
file.write(data)
file.close