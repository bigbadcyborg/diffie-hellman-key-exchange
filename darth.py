# Message Receiver - crypto_chat_server.py
import hashlib, random, os, time
from binascii import hexlify
from socket import *
import lab4_support as ct 
import dh
from lab4_support import DiffieHellman
import numpy as np

#P and G are agreed upon by both Bob and Alice to be 13 and 9 respectively. They are not shared over a network connection, so Darth does not know about it.
P = 13; # A prime number P is taken 
G = 7;  # A primitive root for P, G is taken
d = 6   #Darth's private key
alicePublicKey = 8
def get_dh_sharedsecret(shared_key):
    #create instance for Alice
    darth = DiffieHellman(private_key=d)
   
    #generate public keys
    x = darth.dh_generateSecretKey(shared_key,d,P)
    return x
    
def get_dh_sharedkey():
    #Alice's private key = 8
    darth = DiffieHellman(private_key=d)
    
    #generate bob's public key
    x = darth.dh_generatePublicKey(P,G,alicePublicKey)
    return x
 
def decrypt(ciphertext, usePKI, useDH, serverSecret):
    #msg = ct.decrypt(ciphertext, usePKI, useDH, serverSecret)
    try:
        msg = ct.decrypt(ciphertext, usePKI, useDH, serverSecret)
    except:
        msg = ciphertext
    return msg
    
    
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
     
    #print("Decrypted text: {}".format(decryp_text))
    return decryp_text
 
def main(): 
    # set variables used to determine scheme
    useClientPKI = False;
    useDHKey = True;
    serverSecret = 0
 
    # set the variables used for the server components
    key = "HILL"
    host = "localhost"
    port = 50002
    buf = 1024 * 2
    addr = (host, port)
    UDPSock = socket(AF_INET, SOCK_DGRAM)
    UDPSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)


    # Enable broadcasting mode
    UDPSock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    UDPSock.bind(addr)
    
    print ("Waiting to received shared key from Alice...")
    (data, addr) = UDPSock.recvfrom(buf)
    
    sharedKey = int(str(data, 'utf-8'))
    #print("Shared key between Bob and Alice is", sharedKey)
    sharedSecret = get_dh_sharedsecret(sharedKey)
    
    print("Shared secret between Bob and Alice as calculated by Darth is", sharedSecret)
 
    # welcome to the server message
    print ("Waiting to receive messages...")
    decrypted_key = ct.nRot(key,sharedKey,-1)
 
    try:
        while True:
            data, addr = UDPSock.recvfrom(buf)
            if not data:
                print("Received empty data, skipping...")
                continue
            decrypted_message = ct.cipher_decryption(data.decode(),decrypted_key)
            
            print(f"Message from Alice ({addr}): {decrypted_message.lower()}")

    except KeyboardInterrupt:
        print("\nServer interrupted. Exiting.")

    

    UDPSock.close()
    print("Connection closed.")
        
 
if __name__ == '__main__': 
    main() 
