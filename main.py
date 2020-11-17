import os
import sys


def checkmodexistai(modulei, modulep):
    try:
        return __import__(modulei)
    except ImportError:
        print("\nError 001")
        print("\nYou have not installed: ", modulep)
        print("And therefore have not imported", modulei)
        print("\nPlease Open Your terminal/powershell and enter the following command")
        print("'pip3 install pycryptodome'")
        print("Now relaunch this application")
        input("\nPress ENTER to EXIT")
        sys.exit(1)


# error stuff
def cancelenc():
    print("\nOperation Canceled")
    input("\nPress ENTER to EXIT")


def incorsel():
    print("\nIncorrect Selection")
    input("\nPress ENTER to EXIT")
    sys.exit(1)


# encrypting stuff
def actualencrypt(kfnx, tba, efx):
    from Crypto.Cipher import AES
    print("Generating Key...")
    key = os.urandom(32)
    cipher = AES.new(key, AES.MODE_EAX)
    print("\nWriting Key...")
    file_out = open(kfnx, "wb")
    file_out.write(key)
    file_out.close()
    print("\nReading File...")
    tbe = tba.read()
    tba.close()
    data = tbe
    del tbe
    del tba
    print("\nEncrypting File...")
    print("This may take some time")
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print("\nWriting Encrypted File...")
    file_out = open(efx, "wb")
    [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
    file_out.close()
    del data
    print("\nFinished Encryption")
    input("\nPress ENTER To EXIT")


def tryenc(kfnx, tba):
    print("Please enter a file name for the encrypted file:")
    efn = input()
    efx = str(efn) + str(".pae2xf")
    try:
        open(efx, "rb")
        print("\nA file with the same name as the encrypted file has been detected")
        print("If you continue the file will be overwritten")
        inp = input("\nDo you wish to continue (Y/n): ").lower()
        if inp == "y":
            actualencrypt(kfnx, tba, efx)
        elif inp == "n":
            cancelenc()
            tba.close()
        else:
            incorsel()
            tba.close()
    except FileNotFoundError:
        actualencrypt(kfnx, tba, efx)


def encrypt():
    print("\nThis program encrypts a file using AES 256 Encryption")
    print("\nThe encrypted file will end in a '.pae2xf' extension")
    print("The key file will end in a '.pae2xk' extension")
    print("\nPlease Enter the file name and file extension of the file to encrypt:")
    filename = input()
    try:
        tba = open(filename, "rb")
        print("\nPlease enter a name for the file that will contain the key:")
        kfn = input()
        kfnx = str(kfn) + str(".pae2xk")
        try:
            attempt_open_key = open(kfnx, "rb")
            attempt_open_key.close()
            print("\nA file with the same name as the key has been detected")
            print("If you continue the file will be overwritten")
            inpt = input("\nDo you wish to continue (Y/n): ").lower()
            if inpt == "y":
                tryenc(kfnx, tba)
            elif inpt == "n":
                tba.close()
                cancelenc()
            else:
                tba.close()
                incorsel()
        except FileNotFoundError:
            tryenc(kfnx, tba)
    except FileNotFoundError:
        tba.close()
        print("\nError 100")
        print("\nERROR: File does not exist")
        input("\nPress ENTER to EXIT")
        sys.exit(1)


# decrypting stuff
def actualdecrpyt(encfnx, keyfnx, filename):
    from Crypto.Cipher import AES
    print("\nReading Encrypted File...")
    file_in = open(encfnx, "rb")
    nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
    print("\nReading Key...")
    file_in = open(keyfnx, "rb")
    key = file_in.read()
    file_in.close()
    print("\nDecrypting in progress...")
    print("This may take some time")
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
        print("\nWriting data")
        file = open(filename, "wb")
        file.write(data)
        file.close()
        del data
        print("\nDecryption Complete")
        input("\nPress ENTER to EXIT")
    except ValueError:
        print("\nError 201")
        print("\nThe Key file has been tampered with")
        print("Ensure it is the same file")
        sys.exit(1)


def decyrpt():
    print("\nThis program decrypts AES 256 encryption")
    print("Copy both the encrypted file and key file into the same folder as this program")
    print("\nThe key file should end with '.pae2xk' if it was encrypted with this program")
    print("If not please rename the extension to '.pae2xk'")
    print("\nThe encrypted file should end with '.pae2xf' if it was encrypted with this program")
    print("If not please rename the extension to '.pae2xf'")
    input("\nPress ENTER to continue")
    print("\nPlease enter the name of the file containing the key:")
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
                attempt_to_detect_existing_file = open(filename, "rb")
                attempt_to_detect_existing_file.close()
                print("A file with the same name has been detected")
                print("If you continue it will be overwritten")
                iot = input("\nDo you Wish to Continue (Y/n): ").lower()
                if iot == "y":
                    actualdecrpyt(encfnx, keyfnx, filename)
                elif iot == "n":
                    cancelenc()
                else:
                    incorsel()
            except FileNotFoundError:
                actualdecrpyt(encfnx, keyfnx, filename)
        except FileNotFoundError:
            print("\nError 201")
            print("\nThe Encrypted file was not found")
            print("Ensure it ends with'.pae2xf' and is in the same folder as this program")
            input("\nPress ENTER to EXIT")
    except FileNotFoundError:
        print("\nError 200")
        print("\nThe Key file was not found")
        print("Ensure it ends with'.pae2xk' and is in the same folder as this program")
        input("\nPress ENTER to EXIT")


def main():
    checkmodexistai("Crypto.Cipher", "pycryptodome")
    print("Do you want to ENCRYPT or DECRYPT a file?")
    print("\nEnter 1 to ENCRYPT")
    print("Enter 2 to DECRYPT")
    inl = input("\nSelection: ")
    if inl == "1":
        encrypt()
    elif inl == "2":
        decyrpt()
    else:
        incorsel()


if __name__ == '__main__':
    main()
