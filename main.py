import os
import sys
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import tkinter as tk
from tkinter import filedialog


# Stuff
def write_data(filename, data):
    with open(filename, "wb") as file:
        file.write(data)


def read_data(filename):
    with open(filename, "rb") as file:
        return file.read()


def file_detection(filename):
    try:
        with open(filename, "rb") as file:
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


# AES via RSA Encryption
def aes_from_rsa_encrypt_data(data_to_be_encrypted, public_key):
    aes_key = aes_key_generate()
    aes_encrypted_data = aes_encrypt_data(data_to_be_encrypted, aes_key[0])
    rsa_encrypted_aes_key = rsa_encrypt_data(aes_key[1], public_key)
    return rsa_encrypted_aes_key, aes_encrypted_data[0], aes_encrypted_data[1], aes_encrypted_data[2]


def aes_from_rsa_encrypt(filename_to_encrypt, public_key_filename, encrypted_filename):
    data_to_encrypt = read_data(filename_to_encrypt)
    public_key = read_data(public_key_filename)
    encrypted_data = aes_from_rsa_encrypt_data(data_to_encrypt, public_key)
    with open(encrypted_filename, "wb") as write_encrypted_data:
        [write_encrypted_data.write(i) for i in
         (encrypted_data[0], encrypted_data[1], encrypted_data[2], encrypted_data[3])]


# AES via RSA Decryption
def aes_from_rsa_decrypt_data(rsa_encrypted_aes_key, private_key, ciphertext, tag, nonce):
    random_bytes = rsa_decrypt_data(rsa_encrypted_aes_key, private_key)
    cipher = AES.new(random_bytes, AES.MODE_EAX, nonce)
    decrypted = aes_decrypt_data(ciphertext, tag, cipher)
    return decrypted


def aes_from_rsa_decrypt(encrypted_filename, private_key_filename, decrypted_filename):
    encrypted_data = read_data(encrypted_filename)
    private_key = read_data(private_key_filename)
    encrypted_aes_key = encrypted_data[:512]
    encrypted_aes_data = encrypted_data[512:]
    nonce = encrypted_aes_data[:16]
    tag = encrypted_aes_data[16:32]
    ciphertext = encrypted_aes_data[32:]
    decrypted_data = aes_from_rsa_decrypt_data(encrypted_aes_key, private_key, ciphertext,
                                               tag, nonce)
    write_data(decrypted_filename, decrypted_data)


# User options and displays
def invalid_selection():
    print("\nInvalid Selection")
    input("\nPress ENTER to EXIT")
    sys.exit(1)


def cancel():
    print("\nThe Operation has been canceled")
    input("\nPress ENTER to EXIT")
    sys.exit()


def file_not_found():
    print("\nError: File Does not exit")
    input("\nPress ENTER to EXIT")
    sys.exit(1)


def open_file_dialog():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename()
    if file_path is None:
        cancel()
    else:
        return file_path


def save_file_dialog(file_extension):
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.asksaveasfilename(defaultextension=file_extension)
    if file_path is None:
        cancel()
    else:
        return file_path


# Main Program
def main():
    print("This Program Encrypted or Decrypts Data via AES 256 or RSA 4096")
    print("\nEnter 1 for AES 256 ")
    print("Enter 2 for AES 256 Encryption via RSA 4096")
    print("Enter 3 for RSA 4096 (NOT Recommended)(DOES NOT WORK FOR LARGE FILES)")
    encryption_method_selection = input("\nSelection: ")
    if encryption_method_selection == "1":
        print("\nEnter 1 to Encrypt Data")
        print("Enter 2 to Decrypt Data")
        selection = input("\nSelection: ")
        if selection == "1":
            print("\nThis program encrypts a file using AES 256 Encryption")
            input("\nPress ENTER to select the File to be Encrypted")
            to_encrypt_filename = open_file_dialog()
            if not file_detection(to_encrypt_filename):
                file_not_found()
            else:
                input("\nPress ENTER to select where the Key File will be Saved")
                key_filename = save_file_dialog(".pae2xk")
                input("\nPress ENTER to select where the Encrypted File will be Saved")
                encrypted_filename = save_file_dialog(".pae2xf")
                print("\nEncryption in progress...")
                aes_encrypt(to_encrypt_filename, key_filename, encrypted_filename)
                print("\nEncryption Finished")
                print(f"The Key has been saved at {key_filename}")
                print(f"The Encrypted file has been saved at {encrypted_filename}")
                input("\nPress ENTER to EXIT")
        elif selection == "2":
            print("\nThis program decrypts AES 256 encryption")
            input("\nPress ENTER to select the location of the Key File")
            key_filename = open_file_dialog()
            if not file_detection(key_filename):
                print("\nThe Key file was not found")
                input("\nPress ENTER to EXIT")
                sys.exit(1)
            input("\nPress ENTER to select the location of the Encrypted File")
            encrypted_filename = open_file_dialog()
            if not file_detection(encrypted_filename):
                print("\nThe Encrypted file was not found")
                input("\nPress ENTER to EXIT")
                sys.exit(1)
            input("\nPress ENTER to select where the Decrypted File will be saved")
            decrypted_filename = save_file_dialog("")
            print("\nDecryption in progress...")
            aes_decrypt(encrypted_filename, key_filename, decrypted_filename)
            print("\nDecryption has finished")
            print(f"\nThe decrypted file has been saved at {decrypted_filename}")
            input("\nPress ENTER to EXIT")
        else:
            invalid_selection()
    elif encryption_method_selection == "2":
        print("\nEnter 1 to Encrypt Data")
        print("Enter 2 to Decrypt Data")
        print("Enter 3 to Generate Keys")
        selection = input("\nSelection: ")
        if selection == "1":
            print("\nThis Program Encrypts Data via AES 256 using a RSA 4096 Public Key")
            print("\nPlease Rerun this program to generate RSA keys if you have not done so")
            input("\nPress ENTER to locate the Public Key File")
            key_filename = open_file_dialog()
            if not file_detection(key_filename):
                file_not_found()
            else:
                input("\nPress ENTER to locate the File to be Encrypted")
                to_encrypt_filename = open_file_dialog()
                if not file_detection(to_encrypt_filename):
                    file_not_found()
                else:
                    input("\nPress ENTER to select where the Encrypted File will be saved")
                    encrypted_filename = save_file_dialog(".prs4enc")
                    print("\nBeginning Encryption...")
                    aes_from_rsa_encrypt(to_encrypt_filename, key_filename, encrypted_filename)
                    print("\nEncryption Complete")
                    print(f"The Encrypted file has been saved at {encrypted_filename}")
                    input("\nPress ENTER to EXIT")
        elif selection == "2":
            print("\nThis Program Decrypts Data via 256 using a RSA 4096 Private Key")
            input("\nPress ENTER to locate the Private Key File")
            private_key_filename = open_file_dialog()
            if not file_detection(private_key_filename):
                file_not_found()
            else:
                input("\nPress ENTER to locate the Encrypted File")
                encrypted_filename = open_file_dialog()
                if not file_detection(encrypted_filename):
                    file_not_found()
                else:
                    input("\nPress ENTER to select where the Decrypted File will be saved")
                    decrypted_filename = save_file_dialog("")
                    print("\nBeginning Decryption...")
                    aes_from_rsa_decrypt(encrypted_filename, private_key_filename, decrypted_filename)
                    print("\nDecryption Complete")
                    print(f"The Decrypted File has been saved at {decrypted_filename}")
                    input("\nPress ENTER to EXIT")
        elif selection == "3":
            print("\nThis Program Generates RSA 4096 Key Pairs")
            print("\nThe Public Key can be sent to anyone to Encrypt Data")
            print("The Encrypted Data can only be Decrypted with the Private Key")
            print("\nKEEP THE PRIVATE KEY SAFE")
            input("\n\nPress ENTER to select where the Public Key will be saved")
            pub_key_filename = save_file_dialog(".prs4pub")
            input("\nPress ENTER to select where the Private Key will be saved")
            priv_key_filename = save_file_dialog(".prs4pri")
            print("\nBeginning Key Generation...")
            keys = rsa_key_generate()
            write_data(pub_key_filename, keys[1])
            write_data(priv_key_filename, keys[0])
            print("\nKey Generation Complete")
            print(f"\nThe Public Key has been saved at {pub_key_filename}")
            print(f"The Private Key has been saved at {priv_key_filename}")
            input("\nPress ENTER to EXIT")
        else:
            invalid_selection()
    elif encryption_method_selection == "3":
        print("\nEnter 1 to Encrypt Data")
        print("Enter 2 to Decrypt Data")
        print("Enter 3 to Generate Keys")
        selection = input("\nSelection: ")
        if selection == "1":
            print("\nThis Program Encrypts Data via RSA 4096 Public Key")
            print("\nPlease Rerun this program to generate RSA keys if you have not done so")
            input("\nPress ENTER to locate the Public Key File")
            key_filename = open_file_dialog()
            if not file_detection(key_filename):
                file_not_found()
            else:
                input("\nPress ENTER to locate the File to be Encrypted")
                to_encrypt_filename = open_file_dialog()
                if not file_detection(to_encrypt_filename):
                    file_not_found()
                else:
                    input("\nPress ENTER to select where the Encrypted File will be saved")
                    encrypted_filename = save_file_dialog(".prs4enc")
                    print("\nBeginning Encryption...")
                    rsa_encrypt(to_encrypt_filename, key_filename, encrypted_filename)
                    print("\nEncryption Complete")
                    print(f"The Encrypted file has been saved at {encrypted_filename}")
                    input("\nPress ENTER to EXIT")
        elif selection == "2":
            print("\nThis Program Decrypts Data via RSA 4096 Private Key")
            input("\nPress ENTER to locate the Private Key File")
            private_key_filename = open_file_dialog()
            if not file_detection(private_key_filename):
                file_not_found()
            else:
                input("\nPress ENTER to locate the Encrypted File")
                encrypted_filename = open_file_dialog()
                if not file_detection(encrypted_filename):
                    file_not_found()
                else:
                    input("\nPress ENTER to select where the Decrypted File will be saved")
                    decrypted_filename = save_file_dialog("")
                    print("\nBeginning Decryption...")
                    rsa_decrypt(encrypted_filename, private_key_filename, decrypted_filename)
                    print("\nDecryption Complete")
                    print(f"The Decrypted File has been saved at {decrypted_filename}")
                    input("\nPress ENTER to EXIT")
        elif selection == "3":
            print("\nThis Program Generates RSA 4096 Key Pairs")
            print("\nThe Public Key can be sent to anyone to Encrypt Data")
            print("The Encrypted Data can only be Decrypted with the Private Key")
            print("\nKEEP THE PRIVATE KEY SAFE")
            input("\n\nPress ENTER to select where the Public Key will be saved")
            pub_key_filename = save_file_dialog(".prs4pub")
            input("\nPress ENTER to select where the Private Key will be saved")
            priv_key_filename = save_file_dialog(".prs4pri")
            print("\nBeginning Key Generation...")
            keys = rsa_key_generate()
            write_data(pub_key_filename, keys[1])
            write_data(priv_key_filename, keys[0])
            print("\nKey Generation Complete")
            print(f"\nThe Public Key has been saved at {pub_key_filename}")
            print(f"The Private Key has been saved at {priv_key_filename}")
            input("\nPress ENTER to EXIT")
        else:
            invalid_selection()
    else:
        invalid_selection()


if __name__ == '__main__':
    main()
