import os
import functools
import numpy as np
from operator import xor

C_constant = np.uint64(0x1BD11BDAA9FC1A22)

def splitBytesInWords(key):
    return np.fromstring(key, dtype=np.uint64)

def addIn64bits(a, b):
    return np.add(a, b, dtype=np.uint64)

def subIn64bits(a, b):
    return np.subtract(a, b, dtype=np.uint64)

#################################

class ThreeFish(object):
    def __init__(self, chunks, blsz, key=None):
        self.blocksize = blsz
        self.chunks = chunks
        self.ROT = 33
        self.round_keys = None
        self.master_key = None
        self.master_key_size = None
        self.tweak = None

        # Master key
        if (not key or len(key) != int(blsz/8)):
            key = self.generateKey()
        print("Base key : " + str(key))
        print(str(len(key)) + " bytes key. (" + str(len(key)*8) + " bits)")
        self.constructKeyAndTweaks(key)
        print("Generated " + str(len(self.master_key)-1) + "+1 words key.")
        print("Master Key : " + str(self.master_key))
        print("Tweaks : " + str(self.tweak))

        # Round keys
        self.generateRoundKeys()
        print("Round keys generated. (" + str(len(self.round_keys)) + ")")
        print("Round keys : " + str(self.round_keys))

    def generateKey(self):
        return os.urandom(int(self.blocksize / 8))

    def constructKeyAndTweaks(self, key):
        # key
        self.master_key = splitBytesInWords(key)
        self.master_key_size = len(self.master_key)
        final_word = functools.reduce(xor, self.master_key) ^ C_constant
        self.master_key.resize(self.master_key_size+1)
        self.master_key[-1] = np.uint64(final_word)

        # tweaks
        self.tweak = [self.master_key[2], self.master_key[1]]
        self.tweak.append(self.tweak[0] ^ self.tweak[1])

    def generateRoundKeys(self):
        list = []
        N = self.master_key_size

        for i in range(0, 20):
            Kn = []

            for n in range(0, N):
                temp = self.master_key[(i + n) % (N + 1)]

                if n <= (N-4):
                    Kni = np.uint64(temp)
                elif n == (N-3):
                    Kni = addIn64bits(temp, self.tweak[i % 3])
                elif n == (N-2):
                    Kni = addIn64bits(temp, self.tweak[(i+1) % 3])
                else: # n == N-1
                    Kni = addIn64bits(temp, i)

                Kn.append(Kni)

            list.append(Kn)

        self.round_keys = np.array(list)

    def encryptBlock(self, plain):
        return 1

    def decryptBlock(self, cipher):
        return 1