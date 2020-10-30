import os
import subprocess
import sys


def installmod(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


def checkmodexistai(modulei, modulep):
    try:
        return __import__(modulei)
    except ImportError:
        print("You have not installed: ", modulep)
        print("And therefore not imported", modulei)
        print("Installing Module")
        installmod(modulep)


def decyrpt():
    from Crypto.Cipher import AES
    print()
    print("This program decrypts AES 256 encryption")
    print("Copy both the encrypted file and key file into the same folder as this program")
    print("You only need to follow steps if you didnt encrypt using this program")
    print('1. rename the ecnrypted file to encryptedf')
    print("2. rename the file containing the key to keyf")
    input("Press ENTER to continue")
    print()
    try:
        file_in = open("encryptedf", "rb")
        nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
        file_in = open("keyf", "rb")
        key = file_in.read()
        file_in.close()
        try:
            filename = input("Input File Name for the decrypted file: ")
            print("Decrypting in progress...")
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            file = open(filename, "wb")
            file.write(data)
            file.close()
            print("Decryption Finished")
            input("Press ENTER To EXIT")
        except ValueError:
            print("Error 201")
            print()
            print("The keyf file has been tampered")
            print("Decryption cannot continue")
            input("Press ENTER to EXIT")
    except FileNotFoundError:
        print("Error 200")
        print()
        print("The encrptedf or keyf files were not found")
        input("Press ENTER to EXIT")


def encrypt():
    from Crypto.Cipher import AES
    print()
    print("Initialising... Please Wait")
    key = os.urandom(32)
    cipher = AES.new(key, AES.MODE_EAX)
    file_out = open("keyf", "wb")
    file_out.write(key)
    file_out.close()
    print("This program encrypts a file using AES 256 Encryption")
    print("The key will be saved as 'keyf' and the encrypted file as 'encryptedf'")
    print("Please Enter the file name of the file to encrypt")
    filename = input()
    print("Beginning Encryption...")
    print()
    try:
        tba = open(filename, "rb")
        tbe = tba.read()
        tba.close()
        data = tbe
        ciphertext, tag = cipher.encrypt_and_digest(data)
        file_out = open("encryptedf", "wb")
        [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
        file_out.close()
        print()
        print("Finished Encryption")
        input("Press ENTER To EXIT")
    except FileNotFoundError:
        print("Error 100")
        print()
        print("ERROR: File does not exist")
        input("Press ENTER to EXIT")


checkmodexistai("Crypto.Cipher", "pycryptodome")
print("Do you wish to encrypt or decrypt a file?")
print()
print("Enter 1 if you would like to ENCRYPT")
print("Enter 2 if you would like to DECRYPT")
inp = input()
if inp == "1":
    encrypt()
elif inp == "2":
    decyrpt()
else:
    print("Invalid Selection or an Error Occured")
    input("Press ENTER to EXIT")
