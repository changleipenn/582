
def encrypt(key,plaintext):
    ciphertext=""
    #YOUR CODE here
    ciphertext =''.join([chr(((ord(x)-65)+key)%26+65) for x in plaintext])
    return ciphertext

def decrypt(key,ciphertext):
    plaintext=""
    #YOUR CODE HERE
    plaintext =''.join([chr(((ord(x)-65)-key)%26+65) for x in ciphertext])
    return plaintext


# print(encrypt(1,"ABCD"))
# print(decrypt(-1,"BCDE"))