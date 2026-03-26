import numpy as np


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
    
    # checking validity of the key; finding determinant 
    det = key2d[0][0] * key2d[1][1] - key2d[0][1] * key2d[1][0]
    det_mod26 = det % 26
    try:
        tmp = mod_inverse(det_mod26,26)
    except ValueError:
        raise ValueError("Key matrix determinant invalid.");
        
    
     
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
     
    # checking validity of the key; finding determinant 
    det = key2d[0][0] * key2d[1][1] - key2d[0][1] * key2d[1][0]
    det_mod26 = det % 26
    try:
        det_inverse = mod_inverse(det_mod26,26)
    except ValueError:
        raise ValueError("Key matrix determinant invalid.");
     
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
    
def main():
    
    plaintext = "Secret Message" 
    plaintext = plaintext.upper().replace(" ","") 
    key = "test" 
    key = key.upper().replace(" ","") 
    ciphertext = cipher_encryption(plaintext, key)
    cipher_decryption(ciphertext, key)
    
    return 0
    
if __name__ == '__main__': 
    main()
    
  