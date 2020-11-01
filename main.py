import os


def checkmodexistai(modulei, modulep):
    try:
        return __import__(modulei)
    except ImportError:
        print()
        print("Error 001")
        print()
        print("You have not installed: ", modulep)
        print("And therefore have not imported", modulei)
        print()
        print("Please Open Your terminal/powershell and enter the following command")
        print("'pip3 install pycryptodome'")
        print("Now relaunch this application")
        print()
        input("Press ENTER to EXIT")


# error stuff
def cancelenc():
    print()
    print("Operation Canceled")
    input("Press ENTER to EXIT")


def incorsel():
    print()
    print("Incorrect Selection")
    input("Press ENTER to EXIT")


# encrypting stuff
def actualencrypt(kfnx, tba, efx):
    from Crypto.Cipher import AES
    print("Generating Key...")
    key = os.urandom(32)
    cipher = AES.new(key, AES.MODE_EAX)
    print()
    print("Writing Key...")
    file_out = open(kfnx, "wb")
    file_out.write(key)
    file_out.close()
    print()
    print("Reading File...")
    tbe = tba.read()
    tba.close()
    data = tbe
    print()
    print("Encrypting File...")
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print()
    print("Writing Encrypted File...")
    file_out = open(efx, "wb")
    [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
    file_out.close()
    data = ""
    print(data)
    print("Finished Encryption")
    input("Press ENTER To EXIT")


def tryenc(kfnx, tba):
    print("Please enter a file name for the encrypted file:")
    efn = input()
    efx = str(efn) + str(".pae2xf")
    try:
        open(efx, "rb")
        print()
        print("A file with the same name as the encrypted file has been detected")
        print("If you continue the file will be overwritten")
        print()
        inp = input("Do you wish to continue (Y/n): ")
        if inp == "Y":
            actualencrypt(kfnx, tba, efx)
        elif inp == "n":
            cancelenc()
        else:
            incorsel()
    except FileNotFoundError:
        actualencrypt(kfnx, tba, efx)


def encrypt():
    print()
    print("This program encrypts a file using AES 256 Encryption")
    print()
    print("The encrypted file will end in a '.pae2xf' extension")
    print("The key file will end in a '.pae2xk' extension")
    print()
    print("Please Enter the file name and file extension of the file to encrypt:")
    filename = input()
    try:
        tba = open(filename, "rb")
        print()
        print("Please enter a name for the file that will contain the key:")
        kfn = input()
        kfnx = str(kfn) + str(".pae2xk")
        try:
            open(kfnx, "rb")
            print()
            print("A file with the same name as the key has been detected")
            print("If you continue the file will be overwritten")
            print()
            inpt = input("Do you wish to continue (Y/n): ")
            if inpt == "Y":
                tryenc(kfnx, tba)
            elif inpt == "n":
                cancelenc()
            else:
                incorsel()
        except FileNotFoundError:
            tryenc(kfnx, tba)
    except FileNotFoundError:
        print()
        print("Error 100")
        print()
        print("ERROR: File does not exist")
        input("Press ENTER to EXIT")


# decrypting stuff
def actualdecrpyt(encfnx, keyfnx, filename):
    from Crypto.Cipher import AES
    print()
    print("Reading Encrypted File...")
    file_in = open(encfnx, "rb")
    nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
    print()
    print("Reading Key...")
    file_in = open(keyfnx, "rb")
    key = file_in.read()
    file_in.close()
    print()
    print("Decrypting in progress...")
    print("This may take some time")
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
        print()
        print("Writing data")
        file = open(filename, "wb")
        file.write(data)
        file.close()
        data = ""
        print(data)
        print("Decryption Complete")
        input("Press ENTER to EXIT")
    except ValueError:
        print()
        print("Error 201")
        print()
        print("The Key file has been tampered with")
        print("Ensure it is the same file")


def decyrpt():
    print()
    print("This program decrypts AES 256 encryption")
    print("Copy both the encrypted file and key file into the same folder as this program")
    print()
    print("The key file should end with '.pae2xk' if it was encrypted with this program")
    print("If not please rename the extension to '.pae2xk'")
    print()
    print("The encrypted file should end with '.pae2xf' if it was encrypted with this program")
    print("If not please rename the extension to '.pae2xf'")
    print()
    input("Press ENTER to continue")
    print()
    print("Please enter the name of the file containing the key:")
    keyfn = input()
    keyfnx = str(keyfn) + str(".pae2xk")
    try:
        tok = open(keyfnx, "rb")
        tok.close()
        print("Please enter the name of the encrypted file:")
        encfn = input()
        encfnx = str(encfn) + str(".pae2xf")
        try:
            tof = open(encfnx, "rb")
            tof.close()
            print("Enter a File Name and extension for the decrypted file")
            filename = input()
            try:
                open(filename, "rb")
                print("A file with the same name has been detected")
                print("If you continue it will be overwritten")
                print()
                iot = input("Do you Wish to Continue (Y/n): ")
                if iot == "Y":
                    actualdecrpyt(encfnx, keyfnx, filename)
                elif iot == "n":
                    cancelenc()
                else:
                    incorsel()
            except FileNotFoundError:
                actualdecrpyt(encfnx, keyfnx, filename)
        except FileNotFoundError:
            print()
            print("Error 201")
            print()
            print("The Encrypted file was not found")
            print("Ensure it ends with'.pae2xf' and is in the same folder as this program")
            input("Press ENTER to EXIT")
    except FileNotFoundError:
        print()
        print("Error 200")
        print()
        print("The Key file was not found")
        print("Ensure it ends with'.pae2xk' and is in the same folder as this program")
        input("Press ENTER to EXIT")


# main
checkmodexistai("Crypto.Cipher", "pycryptodome")
print("Do you want to ENCRYPT or DECRYPT a file?")
print()
print("Enter 1 to ENCRYPT")
print("Enter 2 to DECRYPT")
print()
inl = input("Selection: ")
if inl == "1":
    encrypt()
elif inl == "2":
    decyrpt()
else:
    incorsel()
