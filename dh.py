import sys
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
    
        
# dh_generatePublicKey
#  generates and returns a public key using P,G, 
#   and a privateKey chosen by the sender
def dh_generatePublicKey(P,G,privateKey):
    publicKey = power(G, privateKey, P)
    return publicKey
    
    
# dh_generateSecretKey
#   generates and returns a private key using the 
#    publicKey, privateKey and P chosen by the sender
def dh_generateSecretKey(publicKey, privateKey, P):
    secretKey = power(publicKey, privateKey, P)
    return secretKey
    
    
def main(): 
    P = 0; G = 0; x = 0; a = x; 
    y = 0; b = 0; 
    ka = 0; kb = 0
    
    
    # Both the users will be agreed upon the public keys G and P   
    P = 13 # A prime number P is taken  
    print("The value of P: ", P)
    
    G = 7 # A primitive root for P, G is taken  
    print("The value of G: ", G)  
    
    # Alice will choose the private key a   
    a = 21 # a is the chosen private key   
    print("The private key a for Alice: ", a)
    pka = dh_generatePublicKey(P,G,a)
    print("The public key for Alice: ", pka)
    
    
    # Bob will choose the private key b  
    b = 7 # b is the chosen private key  
    print("The private key b for Bob: ", b)  
    pkb = dh_generatePublicKey(P,G,b)
    print("The public key for Bob: ", pkb)
    
    
    # Generating the secret key after the exchange of keys  
    ka = dh_generateSecretKey(pkb, a, P)
    print("Secret key for the Alice is: ", ka)
    
    kb = dh_generateSecretKey(pka, b, P)
    print("Secret Key for the Bob is: ", kb)
    
    return 0
    
    
if __name__ == '__main__': 
    main()