# python-file-encryption
This program requires pycryptodome.
You can install PyCryptodome using pip3 install pycryptodome.
This program encrypts or decrypts a file using aes256 encryption.
The Encryption used is symmetric encryption. This means the key used to encrypt and decrypt is the same.
Keys are generated via os.urandom.


The encrypted file is stored with an extension of '.pae2xf'.
The file containing the key is stored as '.pae2xk' .

This Program was adapted from an example located here: https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes

To encrypt a file
1. Copy and paste the file to the same folder as the program
2. Run the 'main.py' file
3. Select 1
4. Type in the file name and file extension
5. The file with the extension of '.pae2xk' is the file that stores the key. Keep this safe as this is the key used to decrypt the file
6. The file with the extension of '.pae2xf' is the encrypted file. The file is encrypted and can be decrypted with this program with the key file

To decrypt a file
1. Copy and paste the encrypted file and key file to the same folder as this program
2. If the program used to encrypt this file was not this program rename the file extension of the key file to '.pae2xk' adn the encrypted file's extension to '.pae2xf'
3. Run the 'main.py' file to decrypt the encrypted file
5. Enter the name and file extension for the decrypted file 

Error Codes

001 - Pycryptodome is not installed or Crypto.Cipher was not imported sucessfully. Install pycryptodome by launching terminal/powershell and typing 'pip3 install pycryptodome'. Also ensure the location it is installed in is in the Python Path.

100 - The file you are trying to encrypt does not exist. Ensure you have typed in the name and extension of the file and that it is in the same folder as 'main.py'

200 - The key file was not found. Ensure it is in the same folder as 'main.py' and the extension ends with '.pae2xk'

201 - The encrypted file was not found. Ensure it is in the same folder as 'main.py and the extension ends with '.pae2xf'

202 - The key ('.pae2xk') file has been tampered with. Ensure that it is the correct file.

