# python-encrypt-file-aes-256-
This program requires pycryptodome
You can install PyCryptodome using pip3 install pycryptodome 
This program encrypts or decrypts a file using aes256 encryption.
Keys are generated via os.urandom.
The encrypted file is stored as encryptedf
The file containing the key is stored as keyf
To encrypt a file
1. copy and paste the file to the same folder as the program
2. run the encrypt.py program and type in the file name and file extension
3. keyf is the file that stores the key. keep this safe as this is used to decrypt the file
4. encryptedf is the encrypted file
To decrypt a file
1. copy and paste the encrypted file and key file to the same folder as this program
2. rename the encrypted file to encryptf
3. rename the key file to keyf
4. run the decrypt.py program to decrypt the encrypted file
5. enter the name for the decrypted file 
This Program was adapted from an example located here: https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes
