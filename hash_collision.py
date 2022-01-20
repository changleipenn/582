import hashlib
import os

def hash_collision(k):
    if not isinstance(k,int):
        print( "hash_collision expects an integer" )
        return( b'\x00',b'\x00' )
    if k < 0:
        print( "Specify a positive number of bits" )
        return( b'\x00',b'\x00' )
    str = "Hello World"
    byte_str = str.encode('utf-8')
    #Collision finding code goes here
    dic = {}
    while True:
        x = os.urandom(5)
        y = (bin(int(hashlib.sha256(x).hexdigest(), 16))[-k:])
        if y in dic and x!=dic[y]:
            return (dic[y],x)
        else:
            dic[y] = x
    # os.urandom(k+1)
    # x = b'\x00'
    # y = b'\x00'
    
    return( x, y )

print(hash_collision(10))

# input_bytes = "\xFF\x01"
# print(input_bytes)
# output_numbers = list(input_bytes)
# print(output_numbers)
#print(hash_collision(10))