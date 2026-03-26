# Message Sender - crypto_chat_client.py
import hashlib, random, os, time
from binascii import hexlify
from socket import *
import lab4_support as ct
from lab4_support import DiffieHellman
import numpy as np

#P and G are agreed upon by both Bob and Alice. They are not shared over a network connection, so Darth does not know about it.
P = 13; # A prime number P is taken 
G = 7; # A primitive root for P, G is taken 
a = 21	
bobPublicKey = 5 #assume received earlier from Bob for the UDP connection setup simplicity of this lab. In real-world, Bob would send it over UDP.   

def get_dh_sharedsecret():
    #create instance for Alice
    alice = DiffieHellman(private_key=a)
   
    #generate shared key using bobs public key and alice's private key
    # note: this is the key used for encryption
    x = alice.dh_generateSecretKey(bobPublicKey,a,P)
    return x
    
def get_dh_sharedkey():
    #Alice's private key = 21
    alice = DiffieHellman(private_key=a)
    
    #generate Alice's public key
    x = alice.dh_generatePublicKey(P,G,a)
    return x
  
    
 
def main():
    key = "QQNM"
    host = "localhost" # set to IP address of target computer
    port = 50002 #bobs listening port
    addr = (host, port)
    UDPSock = socket(AF_INET, SOCK_DGRAM)
    UDPSock.bind((host,50001)) #alice's port to send from
    UDPSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    
    # Bob and Alice have agreed upon the public keys G and P  
    # no matter what, get the ECC shared key, only use it if the user enables
    x=get_dh_sharedkey()
    print("Alice key for sharing is", x)
    clientSecret = str(get_dh_sharedkey()).encode()
    #print(clientSecret)
    
    sharedSecret = get_dh_sharedsecret()
    print("Shared secret between Bob and Alice as calculated by Alice is", sharedSecret)
    #print(sharedSecret)
    # send the packet over UDP
    UDPSock.sendto(clientSecret, addr)
    
    #decrpyt key with shared key
    decrypted_key = ct.nRot(key,sharedSecret,-1)
    
    print ("Welcome to Crypto-Chat! \n")
    flag = True
    try:
        while flag:
            message = input("Enter your message (or type 'exit' to quit): ").strip()
            message = message.upper().replace(" ","")
            if message.lower() == 'exit':
                print("Exiting Crypto-Chat.")
                flag = False
                break
                
            if not message:
                # If input is empty, skip and continue the loop
                print("Empty message. Please type something or type 'exit' to quit.")
                continue
                
            if any(char == ' ' for char in message):
                print("Invalid character. No spaces. Please try again")
                continue

            
            encrypted_message = ct.cipher_encryption(message,decrypted_key)
            #print(encrypted_message)

            # Send the encrypted message
            UDPSock.sendto(encrypted_message.encode(),addr)
            print(f"Message sent to Bob: {message.lower()}")
            
            
    except KeyboardInterrupt:
        print("\nChat interrupted. Exiting.")
 

    # Close UDP connection
    UDPSock.close()
    print("Connection closed.")
 
if __name__ == '__main__': 
 main() 
