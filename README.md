# python-file-encryption
This program requires pycryptodome.
You can install PyCryptodome using pip3 install pycryptodome.
This program encrypts or decrypts a file using aes256 encryption.
Keys are generated via os.urandom.
AES 256 is symmetrical encryption meaning the same key is used to encrypt and decrypt
RSA 4096 is asymmetrical encryption meaning the public key used to encrypt can only be decrypted by the private key

This Program Encrypts Files with AES 256 or RSA 4096 Encryption

This Program was adapted from an example located here: https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes and https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-rsa

AES 256

To Encrypt:

Copy the file to the same folder as main.py
Follow the Instruction on the program 
The Encrypted File will have a file extension of '.pae2xf'
The Key will have a file extension of '.pae2xk'
The Key should be kept safe as it us the ONLY thing that can decrypt the encrypted file

To Decrypt:

Copy the files to the same folder as main.py
If the file was not encrypted with this program please rename the encrypted file to '.pae2xf' and the key as '.pae2xk'
Follow the instructions on the Program

RSA 4096

To Generate a key pair:

Follow the instructions on the Program 
The Private Key will have a file extension of '.prs4pri'
The Public Key will have a file extension of '.prs4pub'
The Public Key can be used to encrypt data 
ONLY the Private Key can decrypt any data encrypted by the Public Key

To Encrypt:

Copy the Public Key and file to be encrypted to the same folder as the program
Follow the Instructions on the program
If the Public Key was not generated via this program rename the file extension to '.prs4pub'
Only the Private Key can decrypt the data encrypted 

To Decrypt:

Copy the Encrypted file and the Private Key to the same folder as the program
Follow the Instructions on the program 
If the Public Key was not generated via this program rename the file extension to '.prs4pri'
If the encryption was not done via this program rename the encrypted file extension to '.prs4enc'
