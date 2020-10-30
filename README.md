# python-encrypt-file-aes-256-
This program requires pycryptodome.
You can install PyCryptodome using pip3 install pycryptodome.
This program encrypts or decrypts a file using aes256 encryption.
The Encryption used is symmetric encryption. This means the key used to encrypt and decrypt is the same.
Keys are generated via os.urandom.

The encrypted file is stored as encryptedf.
The file containing the key is stored as keyf.

This Program was adapted from an example located here: https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes

To encrypt a file
1. Copy and paste the file to the same folder as the program
2. Run the 'main.py' file
3. Select 1
4. Type in the file name and file extension
5. 'keyf' is the file that stores the key. Keep this safe as this is the key used to decrypt the file
6. 'encryptedf' is the encrypted file

To decrypt a file
1. Copy and paste the encrypted file and key file to the same folder as this program
2. Rename the encrypted file to 'encryptf'
3. Rename the key file to 'keyf'
4. Run the 'main.py' file to decrypt the encrypted file
5. Enter the name and file extension for the decrypted file 

Error Codes

100 - The file you are trying to encrypt does not exist. Ensure you have typed in the name and extension of the file and that it is in the same folder as 'main.py'

200 - The encryptedf or keyf files does not exist/s. Ensure you renamed the file containing the key to 'keyf' (without any extensions) and 'encryptedf' (without any extensions as well) and that the file are in the same folder as 'main.py'

201 - The 'keyf' file has been tampered with. Ensure that it is the correct file and is the same binary as when you generated it
