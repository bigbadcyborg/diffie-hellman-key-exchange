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
G = 7; # A primitive root for P, G is taken 
b = 3 #Bob's private key	
a = 8 #Alice's public key
def get_dh_sharedsecret():
    #create instance for Alice
    bob = DiffieHellman(private_key=b)
   
    #generate public keys
    x = bob.dh_generateSecretKey(bobPublicKey,a,P)
    return x
    
def get_dh_sharedkey():
    #Alice's private key = 8
    alice = DiffieHellman(private_key=a)
    
    #generate bob's public key
    x = bob.dh_generatePublicKey(P,G,a)
    return x

def decrypt(ciphertext, usePKI, useDH, serverSecret):
    try:
        msg = ct.decrypt(ciphertext, usePKI, useDH, serverSecret)
    except:
        msg = ciphertext
    return msg
    
 
def main(): 
    # set variables used to determine scheme
    useClientPKI = False;
    useDHKey = True;
    serverSecret = 0

  
    # set the variables used for the server components
    key = "QQNM"
    host = "localhost" #Enter correct IP address here
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
    
    #generate bob's secret key from Alice's shared key
    sharedKey = int(str(data, 'utf-8'))
    bob = DiffieHellman(private_key=b)
    sharedKey = bob.dh_generateSecretKey(sharedKey,b,P)
    print("Shared key between Bob and Alice is", sharedKey)
 
    # welcome to the server message
    print ("Waiting to receive messages...")
    
    #decrypt key with shared key
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
