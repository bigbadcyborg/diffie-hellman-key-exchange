# Chat Encryption Helper - ch9_crypto_chat.py
import math
import os, base64, json
#from Crypto.Cipher import PKCS1_OAEP, AES
#from Crypto.PublicKey import RSA, ECC
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
import numpy as np

    # power
    #  power(a,b,p) that returns a^b mod p using Python’s 
    #   pow function. Handle special case if b == 1
def power(a,b,p):
    val = -1
        
    if b == 1:
        val = a % p
    else:
        val = pow(a,b,p)
            
    return val
    
def mod_inverse(a,m):
    a = a % m
    for x in range(1,m):
        if (a * x) % m == 1:
            return x
    raise ValueError("Modular inverse DNE.")
    
#Convert characters in the matrix to their corresponding numeric values (0-25).
def convert_char_to_number(matrix):
    return [[ord(char.upper()) - ord('A') for char in row] for row in matrix]
    
def convert_key_to_numbers(key2d):
    return [[ord(char.upper()) - ord('A') for char in row] for row in key2d]


def _hill_key_det_mod_26(key2d_nums):
    return (
        key2d_nums[0][0] * key2d_nums[1][1]
        - key2d_nums[0][1] * key2d_nums[1][0]
    ) % 26


def _require_invertible_hill_key(key2d_nums):
    det_mod26 = _hill_key_det_mod_26(key2d_nums)
    if math.gcd(det_mod26, 26) != 1:
        raise ValueError(
            "This Hill cipher key is not usable: the 2x2 matrix determinant is "
            f"congruent to {det_mod26} modulo 26, but it must be coprime with 26 "
            "(not divisible by 2 or 13). Pick a different four-letter key."
        )
    return det_mod26


def cipher_decryption(cipher, key): 
  
    # Handle condition if the message length is odd. 
    if len(cipher) % 2 != 0:
        raise ValueError("Error: odd length of ciphertext")
     
    # Convert msg to matrices 
    cipher_nums = [ord(char.upper()) - ord('A') for char in cipher]

    # Convert key to 2x2 
    key2d = [[key[0], key[1]],
            [key[2], key[3]]]
    #print(key2d)
    #convert to key2d to numerical representation
    key2d = convert_key_to_numbers(key2d)
    #print(key2d)
     
    det_mod26 = _require_invertible_hill_key(key2d)
    det_inverse = mod_inverse(det_mod26, 26)

    # find transpose of cofactor matrix
    # find transpose  
    # find minor 
    # change signs 
    adjugate = np.array([[key2d[1][1], -key2d[0][1]],
                         [-key2d[1][0], key2d[0][0]]])
     
     
    # multiplying multiplicative inverse with adjugate matrix 
    # ensure all positive elements
    inverse_key = (det_inverse * adjugate) % 26
    inverse_key = np.array([[int(num) % 26 for num in row] for row in inverse_key])

     
    # decrypt the ciphertext
    decrypted_nums = []
    for i in range(0, len(cipher_nums), 2):
        pair = np.array(cipher_nums[i:i+2])
        decrypted_pair = np.dot(inverse_key, pair) % 26
        decrypted_nums.extend(decrypted_pair) 
     
    # Convert cipher to plaintext 
    decryp_text = ''.join(chr(num + ord('A')) for num in decrypted_nums)
     
    #print("Decrypted text: {}".format(decryp_text))
    return decryp_text
    
    
# cipher_encryption
#  uses Hill 2x2 cipher
def cipher_encryption(plain, key):
    #print("Plaintext:", plain)
    #print("Key:", key)

    # Handle condition if the message length is odd by padding with '+' char
    if len(plain) % 2 != 0:
        plain += 'X'
        
    # handle length err
    if len(key) != 4:
        raise ValueError("Key must contain exactly 4 elements for a 2x2 matrix.")

    # Convert msg to matrices
    pTxtNums = [ord(char.upper()) - ord('A') for char in plain]
    #print(pTxtNums)

    # Convert key to 2x2 
    key2d = [[key[0], key[1]],
            [key[2], key[3]]]
    #print(key2d)
    #convert to key2d to numerical representation
    key2d = convert_key_to_numbers(key2d)
    #print(key2d)
    
    _require_invertible_hill_key(key2d)

    # finding multiplicative inverse and implementing steps to encrypt 
    #text
    encrypted_nums = []
    for i in range(0, len(pTxtNums), 2):
        pair = np.array(pTxtNums[i:i+2])
        encrypted_pair = np.dot(key2d, pair) % 26
        encrypted_nums.extend(encrypted_pair)
 
    
    #convert back to letters
    encryp_text = ''.join(chr(num + ord('A')) for num in encrypted_nums)
    #print("Encrypted text: {}".format(encryp_text))
    
    return encryp_text
    
def nRot(inputText, N, D):
    # Check if N is valid
    if N < 1:
        raise ValueError("N must be >= 1.")
    # Check if D is valid
    if D not in [1, -1]:
        raise ValueError("D must be +1 (right) or -1 (left).")

    # Step 1: Reverse the input text
    reversed_text = inputText[::-1]

    # Define ASCII printable character range
    ascii_start = 34  # Start after space and '!' (see ascii table)
    ascii_end = 126   # '~' is the end
    ascii_range = ascii_end - ascii_start + 1

    # Step 2: Shift characters
    encrypted_text = ""
    for char in reversed_text:
        if ord(char) < ascii_start or ord(char) > ascii_end:
            raise ValueError("Input contains invalid characters.")
        # Shift ASCII characters cyclically within the range
        shifted_char = chr(ascii_start + (ord(char) - ascii_start + (D * N)) % ascii_range)
        encrypted_text += shifted_char

    return encrypted_text

class DiffieHellman:
    def __init__(self, private_key, public_key=None):
            self.private_key = private_key
            self.public_key = public_key

        
            
    # dh_generatePublicKey
    #  generates and returns a public key using P,G, 
    #   and a privateKey chosen by the sender
    def dh_generatePublicKey(self,P,G,privateKey):
        publicKey = power(G, privateKey, P)
        self.public_key = publicKey
        return publicKey
        
        
    # dh_generateSecretKey
    #   generates and returns a private key using the 
    #    publicKey, privateKey and P chosen by the sender
    def dh_generateSecretKey(self,publicKey, privateKey, P):
        secretKey = power(publicKey, privateKey, P)
        return secretKey
     
    # encryption method used by all calls
    def encrypt(self,message, usePKI, useDH, dhSecret):
        em=cipherEncrypt(message, dhSecret)
        return em
     
    # decryption method used by all calls
    def decrypt(self,message, usePKI, useDH, dhSecret):
        dm=cipherEncrypt(message, dhSecret)
        return dm
     
    # decrypt using RSA (for future reference, not needed for this homework)
    #def decrypt_rsa(ciphertext):
    #    return ciphertext
     
    # encrypt using RSA (for future reference, not needed for this homework)
    #def encrypt_rsa(message):
    #    return message
     
    # check client commands (for future reference, not needed for this homework)
    def check_client_command(data):
        return 1
     
    # check server commands (for future reference, not needed for this homework)
    def check_server_command(data):
        return 1
        
    def reversed_string(a_string):
        return a_string[::-1]

    def mod_inverse(a,m):
        a = a % m
        for x in range(1,m):
            if (a * x) % m == 1:
                return x
        raise ValueError("Modular inverse DNE.")
        
    #Convert characters in the matrix to their corresponding numeric values (0-25).
    def convert_char_to_number(matrix):
        return [[ord(char.upper()) - ord('A') for char in row] for row in matrix]
        
    def convert_key_to_numbers(key2d):
        return [[ord(char.upper()) - ord('A') for char in row] for row in key2d]



    # cipher_encryption
    #  uses Hill 2x2 cipher
    def cipher_encryption(plain, key):
        print("Plaintext:", plain)
        print("Key:", key)

        # Handle condition if the message length is odd by padding with '+' char
        if len(plain) % 2 != 0:
            plain += 'X'
            
        # handle length err
        if len(key) != 4:
            raise ValueError("Key must contain exactly 4 elements for a 2x2 matrix.")

        # Convert msg to matrices
        pTxtNums = [ord(char.upper()) - ord('A') for char in plain]
        print(pTxtNums)

        # Convert key to 2x2 
        key2d = [[key[0], key[1]],
                [key[2], key[3]]]
        print(key2d)
        #convert to key2d to numerical representation
        key2d = convert_key_to_numbers(key2d)
        print(key2d)
        
        _require_invertible_hill_key(key2d)

        # finding multiplicative inverse and implementing steps to encrypt 
        #text
        encrypted_nums = []
        for i in range(0, len(pTxtNums), 2):
            pair = np.array(pTxtNums[i:i+2])
            encrypted_pair = np.dot(key2d, pair) % 26
            encrypted_nums.extend(encrypted_pair)
     
        
        #convert back to letters
        encryp_text = ''.join(chr(num + ord('A')) for num in encrypted_nums)
        print("Encrypted text: {}".format(encryp_text))
        
        return encryp_text

    
      
      
    def cipher_decryption(cipher, key): 
      
        # Handle condition if the message length is odd. 
        if len(cipher) % 2 != 0:
            raise ValueError("Error: odd length of ciphertext")
         
        # Convert msg to matrices 
        cipher_nums = [ord(char.upper()) - ord('A') for char in cipher]

        # Convert key to 2x2 
        key2d = [[key[0], key[1]],
                [key[2], key[3]]]
        print(key2d)
        #convert to key2d to numerical representation
        key2d = convert_key_to_numbers(key2d)
        print(key2d)
         
        det_mod26 = _require_invertible_hill_key(key2d)
        det_inverse = mod_inverse(det_mod26, 26)

        # find transpose of cofactor matrix
        # find transpose  
        # find minor 
        # change signs 
        adjugate = np.array([[key2d[1][1], -key2d[0][1]],
                             [-key2d[1][0], key2d[0][0]]])
         
         
        # multiplying multiplicative inverse with adjugate matrix 
        # ensure all positive elements
        inverse_key = (det_inverse * adjugate) % 26
        inverse_key = np.array([[int(num) % 26 for num in row] for row in inverse_key])

         
        # decrypt the ciphertext
        decrypted_nums = []
        for i in range(0, len(cipher_nums), 2):
            pair = np.array(cipher_nums[i:i+2])
            decrypted_pair = np.dot(inverse_key, pair) % 26
            decrypted_nums.extend(decrypted_pair) 
         
        # Convert cipher to plaintext 
        decryp_text = ''.join(chr(num + ord('A')) for num in decrypted_nums)
         
        print("Decrypted text: {}".format(decryp_text))
        return decryp_text

        
        
        
        
