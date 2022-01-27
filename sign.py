from fastecdsa.curve import secp256k1
from fastecdsa.keys import export_key, gen_keypair

from fastecdsa import curve, ecdsa, keys, point
from hashlib import sha256

def sign(m):
	#generate public key
	#Your code here
	priv_key, public_key = keys.gen_keypair(secp256k1)
	#print("private key is "+str(priv_key))
	#print("public key is "+str(public_key[0]))
	#public_key = None
	#generate signature
	#Your code here
	r, s = ecdsa.sign(m, priv_key,hashfunc=sha256,curve=secp256k1)
	#valid = ecdsa.verify((r, s), m, public_key, hashfunc=sha256,curve=secp256k1)
	#print(valid)

	assert isinstance( public_key, point.Point )
	assert isinstance( r, int )
	assert isinstance( s, int )
	return( public_key, [r,s] )

x = sign("xyz")
#print(x[0])
print(x[1][0])
print(x[1][1])
