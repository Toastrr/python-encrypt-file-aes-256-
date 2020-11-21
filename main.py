import os
import sys
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# Stuff
def write_data(filename, data):
    file = open(filename, "wb")
    file.write(data)
    file.close()
    del data, file


def read_data(filename):
    file = open(filename, "rb")
    data_read = file.read()
    file.close()
    del file
    return data_read


def file_detection(filename):
    try:
        file = open(filename, "rb")
        file.close()
        return True
    except FileNotFoundError:
        return False


# AES Encrypt
def aes_key_generate():
    random_bytes = os.urandom(32)
    cipher = AES.new(random_bytes, AES.MODE_EAX)
    return cipher, random_bytes


def aes_encrypt_data(data_to_encrypt, cipher):
    ciphertext, tag = cipher.encrypt_and_digest(data_to_encrypt)
    return cipher.nonce, tag, ciphertext


def aes_encrypt(filename_to_encrypt, key_filename, encrypted_filename):
    cipher = aes_key_generate()
    write_data(key_filename, cipher[1])
    data_to_encrypt = read_data(filename_to_encrypt)
    encrypted_data = aes_encrypt_data(data_to_encrypt, cipher[0])
    del data_to_encrypt
    write_encrypted_data = open(encrypted_filename, "wb")
    [write_encrypted_data.write(i) for i in (encrypted_data[0], encrypted_data[1], encrypted_data[2])]
    write_encrypted_data.close()
    del encrypted_data, write_encrypted_data


# AES Decrypt
def aes_read_encrypted_data(filename):
    encrypted_file = open(filename, "rb")
    nonce, tag, ciphertext = [encrypted_file.read(x) for x in (16, 16, -1)]
    encrypted_file.close()
    del encrypted_file
    return nonce, tag, ciphertext


def aes_decrypt_data(ciphertext, tag, cipher):
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    del ciphertext, tag, cipher
    return decrypted_data


def aes_decrypt(encrypted_filename, key_filename, decrypted_filename):
    encrypted_data = aes_read_encrypted_data(encrypted_filename)
    random_bytes = read_data(key_filename)
    cipher = AES.new(random_bytes, AES.MODE_EAX, encrypted_data[0])
    del random_bytes
    decrypted_data = aes_decrypt_data(encrypted_data[2], encrypted_data[1], cipher)
    del cipher, encrypted_data
    write_data(decrypted_filename, decrypted_data)
    del decrypted_data


# RSA
# Generate key
def rsa_key_generate():
    key = RSA.generate(4096)
    private_key = key.exportKey()
    public_key = key.publickey().export_key()
    del key
    return private_key, public_key


# RSA Encrypt
def rsa_encrypt_data(data, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    del recipient_key
    encrypted_data = cipher_rsa.encrypt(data)
    del cipher_rsa, data
    return encrypted_data


def rsa_encrypt(filename_to_encrypt, public_key_filename, encrypted_filename):
    data_to_encrypt = read_data(filename_to_encrypt)
    public_key = read_data(public_key_filename)
    encrypted_data = rsa_encrypt_data(data_to_encrypt, public_key)
    del data_to_encrypt, public_key
    write_data(encrypted_filename, encrypted_data)


# RSA Decrypt
def rsa_decrypt_data(encrypted_data, private_key):
    private_key = RSA.import_key(private_key)
    rsa_cipher = PKCS1_OAEP.new(private_key)
    del private_key
    decrypted_data = rsa_cipher.decrypt(encrypted_data)
    del rsa_cipher
    return decrypted_data


def rsa_decrypt(encrypted_filename, private_key_filename, decrypted_filename):
    encrypted_data = read_data(encrypted_filename)
    private_key = read_data(private_key_filename)
    decrypted_data = rsa_decrypt_data(encrypted_data, private_key)
    del encrypted_data, private_key
    write_data(decrypted_filename, decrypted_data)
    del decrypted_data


def invalid_selection():
    print("Invalid Selection")
    input("Press ENTER to EXIT")
    sys.exit(1)


def cancel():
    print("The Operation has been canceled")
    input("Press ENTER to EXIT")
    sys.exit()


def main():
    print("This Program Encrypted or Decrypts Data via AES 256 or RSA 4096")
    print("\nEnter 1 for AES 256")
    print("Enter 2 for RSA 4096")
    encryption_method_selection = input("Selection: ")
    if encryption_method_selection == "1":
        print("\nEnter 1 to Encrypt Data")
        print("Enter 2 to Decrypt Data")
        selection = input("Selection: ")
        if selection == "1":
            print("\nThis program encrypts a file using AES 256 Encryption")
            print("\nThe encrypted file will end in a '.pae2xf' extension")
            print("The key file will end in a '.pae2xk' extension")
            print("\nPlease Enter the file name and file extension of the file to encrypt:")
            to_encrypt_filename = input()
            if not file_detection(to_encrypt_filename):
                print("Error: File Does not exit")
                input("Press ENTER to EXIT")
                sys.exit(1)
            else:
                print("\nPlease enter a name for the file that will contain the key:")
                key_filename = input()
                if key_filename[-7:] != ".pae2xk":
                    key_filename = str(key_filename) + str(".pae2xk")
                if file_detection(key_filename):
                    print("A file with the same name has been detected")
                    print("If you continue the file will be overwritten")
                    over_write_key = input("\nDo you wish to continue (Y/n): ").lower()
                    if over_write_key == "n":
                        cancel()
                    if over_write_key != "y":
                        invalid_selection()
                print("Please enter a file name for the encrypted file:")
                encrypted_filename = input()
                if encrypted_filename[-7:] != ".pae2xf":
                    encrypted_filename = str(encrypted_filename) + str(".pae2xf")
                if file_detection(encrypted_filename):
                    print("A file with the same name has been detected")
                    print("If you continue the file will be overwritten")
                    over_write_encrypted = input("\nDo you wish to continue (Y/n): ").lower()
                    if over_write_encrypted == "n":
                        cancel()
                    if over_write_encrypted != "y":
                        invalid_selection()
                print("\nEncryption in progress...")
                aes_encrypt(to_encrypt_filename, key_filename, encrypted_filename)
                print("\nEncryption Finished")
                print(f"The Key has been saved as {key_filename}")
                print(f"The Encrypted file has been saved as {encrypted_filename}")
                input("\nPress ENTER to EXIT")
        elif selection == "2":
            print("\nThis program decrypts AES 256 encryption")
            print("Copy both the encrypted file and key file into the same folder as this program")
            print("\nThe key file should end with '.pae2xk' if it was encrypted with this program")
            print("If not please rename the extension to '.pae2xk'")
            print("\nThe encrypted file should end with '.pae2xf' if it was encrypted with this program")
            print("If not please rename the extension to '.pae2xf'")
            input("\nPress ENTER to continue")
            print("\nPlease enter the name of the file containing the key:")
            key_filename = input()
            if key_filename[-7:] != ".pae2xk":
                key_filename = str(key_filename) + str(".pae2xk")
            if not file_detection(key_filename):
                print("\nThe Key file was not found")
                print("Ensure it ends with'.pae2xk' and is in the same folder as this program")
                input("\nPress ENTER to EXIT")
                sys.exit(1)
            print("Please enter the name of the encrypted file:")
            encrypted_filename = input()
            if encrypted_filename[-7:] != ".pae2xf":
                encrypted_filename = str(encrypted_filename) + str(".pae2xf")
            if not file_detection(encrypted_filename):
                print("\nThe Encrypted file was not found")
                print("Ensure it ends with'.pae2xf' and is in the same folder as this program")
                input("\nPress ENTER to EXIT")
                sys.exit(1)
            print("Enter a File Name and extension for the decrypted file")
            decrypted_filename = input()
            if file_detection(decrypted_filename):
                print("A file with the same name has been detected")
                print("If you continue the file will be overwritten")
                over_write_decrypted = input("\nDo you wish to continue (Y/n): ").lower()
                if over_write_decrypted == "n":
                    cancel()
                if over_write_decrypted != "y":
                    invalid_selection()
            print("\nDecryption in progress...")
            aes_decrypt(encrypted_filename, key_filename, decrypted_filename)
            print("\nDecryption has finished")
            print(f"\nThe decrypted file has been saved as {decrypted_filename}")
            input("\nPress ENTER to EXIT")
        else:
            invalid_selection()
    elif encryption_method_selection == "2":
        print("\nEnter 1 to Encrypt Data")
        print("Enter 2 to Decrypt Data")
        print("Enter 3 to Generate Keys")
        selection = input("Selection: ")
        if selection == "1":
            print("\nThis Program Encrypts Data via RSA 4096 Public Key")
            print("Please Copy The File to be Encrypted and Public Key into the same Folder as this Program")
            print("\nIf the public key was NOT generated via this Program please rename the file extension to "
                  "'.prs4pub'")
            print("The Encrypted file extension will end in '.prs4enc'")
            input("\nPress ENTER to CONTINUE")
            print("\nPlease Enter the file name of the public key")
            key_filename = input()
            if key_filename[-8:] != ".prs4pub":
                key_filename = str(key_filename) + str('.prs4pub')
            if not file_detection(key_filename):
                print("\nError: File Does not exit")
                input("Press ENTER to EXIT")
            else:
                print("\nPlease Enter the file name and file extension of the file to encrypt:")
                to_encrypt_filename = input()
                if not file_detection(to_encrypt_filename):
                    print("\nError: File Does not exit")
                    input("Press ENTER to EXIT")
                else:
                    print("\nPlease enter a file name for the encrypted file:")
                    encrypted_filename = input()
                    if encrypted_filename[-8:] != '.prs4enc':
                        encrypted_filename = str(encrypted_filename) + str('.prs4enc')
                    print("\nBeginning Encryption...")
                    rsa_encrypt(to_encrypt_filename, key_filename, encrypted_filename)
                    print("\nEncryption Complete")
                    print(f"The Encrypted file has been saved as {encrypted_filename}")
                    input("Press ENTER to EXIT")
        elif selection == "2":
            print("\nThis Program Decrypts Data via RSA 4096 Private Key")
            print("Please Copy The File to be Encrypted and Private Key into the same Folder as this Program")
            print("\nIf the private key was NOT generated via this Program please rename the file extension to "
                  "'.prs4pri'")
            print("\nIf the encrypted file was not encrypted via this program please rename the file extension to "
                  "'.prs4enc'")
            input("\nPress ENTER to CONTINUE")
            print("\nPlease Enter the Private Key file name")
            private_key_filename = input()
            if private_key_filename[-8:] != '.prs4pri':
                private_key_filename = str(private_key_filename) + str('.prs4pri')
            if not file_detection(private_key_filename):
                print("\nError: File Does not exit")
                input("Press ENTER to EXIT")
            else:
                print("\nPlease Enter the Encrypted file name")
                encrypted_filename = input()
                if encrypted_filename[-8:] != '.prs4enc':
                    encrypted_filename = str(encrypted_filename) + str('.prs4enc')
                if not file_detection(encrypted_filename):
                    print("\nError: File Does not exit")
                    input("Press ENTER to EXIT")
                else:
                    print("\nEnter a File Name and extension for the decrypted file")
                    decrypted_filename = input()
                    if file_detection(decrypted_filename):
                        print("A file with the same name has been detected")
                        print("If you continue the file will be overwritten")
                        over_write_decrypted = input("\nDo you wish to continue (Y/n): ").lower()
                        if over_write_decrypted == 'n':
                            cancel()
                        if over_write_decrypted != 'y':
                            invalid_selection()
                    print("\nBeginning Decryption...")
                    rsa_decrypt(encrypted_filename, private_key_filename, decrypted_filename)
                    print("\nDecryption Complete")
                    print(f"The Decrypted File has been saved as {decrypted_filename}")
                    input("\nPress ENTER to EXIT")
        elif selection == "3":
            print("\nThis Program Generates RSA 4096 Key Pairs")
            print("The Public Key will end with a Extension of '.prs4pub'")
            print("The Private Key will end with a Extension of '.prs4pri'")
            print("\nThe Public Key can be sent to anyone to Encrypt Data")
            print("The Encrypted Data can only be Decrypted with the Private Key")
            print("\nKEEP THE PRIVATE KEY SAFE")
            print("\nEnter a file name for the Public Key ")
            pub_key_filename = input()
            if pub_key_filename[-8:] != ".prs4pub":
                pub_key_filename = str(pub_key_filename) + str(".prs4pub")
            if file_detection(pub_key_filename):
                print("A file with the same name has been detected")
                print("If you continue the file will be overwritten")
                over_write_rsa_pub_key = input("\nDo you wish to continue (Y/n): ").lower()
                if over_write_rsa_pub_key == "n":
                    cancel()
                if over_write_rsa_pub_key != "y":
                    invalid_selection()
            print("\nEnter a file name for the Private Key")
            priv_key_filename = input()
            if priv_key_filename[-8:] != ".prs4pri":
                priv_key_filename = str(priv_key_filename) + str(".prs4pri")
            if file_detection(priv_key_filename):
                print("A file with the same name has been detected")
                print("If you continue the file will be overwritten")
                over_write_rsa_priv_key = input("\nDo you wish to continue (Y/n): ").lower()
                if over_write_rsa_priv_key == "n":
                    cancel()
                if over_write_rsa_priv_key != "y":
                    invalid_selection()
            print("\nBeginning Key Generation...")
            keys = rsa_key_generate()
            write_data(pub_key_filename, keys[1])
            write_data(priv_key_filename, keys[0])
            print("\nKey Generation Complete")
            input("Press ENTER to EXIT")
        else:
            invalid_selection()
    else:
        invalid_selection()


if __name__ == '__main__':
    main()
