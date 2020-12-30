# python-file-encryption
This program requires pycryptodome.
You can install PyCryptodome using pip3 install pycryptodome.
This program encrypts or decrypts a file using aes256 encryption.
Keys are generated via os.urandom.

AES 256 is symmetrical encryption meaning the same key is used to encrypt and decrypt

AES 256 via RSA 4096 is a method of which AES 256 is used to encrypt the file and RSA 4096 is used to encrypt the AES Key

RSA 4096 is asymmetrical encryption meaning the public key used to encrypt can only be decrypted by the private key


This Program Encrypts Files with AES 256 or RSA 4096 Encryption

This Program was adapted from an example located here: https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes and https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-rsa


AES 256


To Encrypt:

Copy the file to the same folder as main.py
Follow the Instruction on the program 
The Key should be kept safe as it us the ONLY thing that can decrypt the encrypted file

To Decrypt:

Follow the instructions on the Program


RSA 4096/AES 256 Via RSA 4096


To Generate a key pair:

Follow the instructions on the Program 
The Public Key can be used to encrypt data 
ONLY the Private Key can decrypt any data encrypted by the Public Key

To Encrypt:

Copy the Public Key and file to be encrypted to the same folder as the program
Follow the Instructions on the program
Only the Private Key can decrypt the data encrypted 

To Decrypt:

Copy the Encrypted file and the Private Key to the same folder as the program
Follow the Instructions on the program 
