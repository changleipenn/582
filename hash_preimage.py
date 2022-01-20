import hashlib
import os

#take a single input, return a single variable x s.t. sha(x) match the target string
def hash_preimage(target_string):
    if not all( [x in '01' for x in target_string ] ):
        print( "Input should be a string of bits" )
        return


    ll = len(target_string)
    #print(ll)
    while True:
        x = os.urandom(5)
        y = (bin(int(hashlib.sha256(x).hexdigest(), 16))[-ll:])
        #print(y)
        if y == target_string:
            return x


hash_preimage("01")
