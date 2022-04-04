from zksk import Secret, DLRep
from zksk import utils

def ZK_equality(G,H):

    #Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)


    #Generate a NIZK proving equality of the plaintexts

    #Return two ciphertexts and the proof

    # Setup: Peggy and Victor agree on two group generators.
    # Since Peggy is *committing* rather than encrypted Peggy doesn't know DL_G(H)
    #G, H = utils.make_generators(num=2, seed=42)

    # Setup: generate a secret randomizer for the commitment scheme.
    r1 = Secret(utils.get_random_num(bits=128))
    r2 = Secret(utils.get_random_num(bits=128))

    # This is Peggy's secret bit.
    #top_secret_bit = 1
    m = 1

    # A Pedersen commitment to the secret bit.
    #C = top_secret_bit * G + r.value * H
    C1 = r1 * G
    C2 = r1 * H  + m * G
    D1 = r2 * G
    D2 =  r2* H + m * G
    

    # Peggy's definition of the proof statement, and proof generation.
    # (The first or-clause corresponds to the secret value 0, and the second to the value 1. Because
    # the real value of the bit is 1, the clause that corresponds to zero is marked as simulated.)
    #stmt = DLRep(C, r * H, simulated=True) | DLRep(C - G, r * H)
    stmt = DLRep(C1,r1*G) & DLRep(C2,r1*H+m*G) & DLRep(D1,r2*G) & DLRep(D2,r2*H+m*G)
    zk_proof = stmt.prove()


    return (C1,C2), (D1,D2), zk_proof

