import math

def num_BTC(b):
    c = float(0)
    k = b // 210000
    r = b % 210000
    fir = 10500000 * (1-pow(0.5,k)) / 0.5
    sec = r * 50 * pow(0.5,k)
    return fir+sec

#print(num_BTC(210001))


