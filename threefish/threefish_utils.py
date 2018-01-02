import os
import functools
import numpy as np
import binascii
from operator import xor

# ================================================================================
#
#   THREE FISH : fonctions utiles
#
# ================================================================================

"""
Transforme une suite de bytes (comme une clé par exemple), en mots de 64 bits exactement
"""
def splitBytesInWords(key, normalLength):
    if len(key) < normalLength:
        key += b'\x00' * (normalLength-len(key))
    return np.fromstring(key, dtype=np.uint64)

"""
Transforme des mots de 64 bits en binary string
"""
def joinWordsToBytes(data):
    try:
        return data.tostring()
    except AttributeError:
        return np.uint64(data).tostring()

"""
Somme sans retenue dans 64 bits
"""
def addIn64bits(a, b):
    return np.add(a, b, dtype=np.uint64)

"""
Soustraction dans 64 bits
"""
def subIn64bits(a, b):
    return np.subtract(a, b, dtype=np.uint64)

"""
Permutation circulaire vers la GAUCHE dans 64 bits
"""
def rotateLeft64bits(n, rot):
    mask = 2 ** 64 - 1
    n = int(n & mask)
    return np.uint64(((n << rot) & mask) | (n >> (64 - rot)))

"""
Permutation circulaire vers la DROITE dans 64 bits
"""
def rotateRight64bits(n, rot):
    mask = 2 ** 64 - 1
    n = int(n & mask)
    return np.uint64((n >> rot) | ((n << (64 - rot)) & mask))

# ================================================================================
#
#   THREE FISH : classe
#
# ================================================================================

class ThreeFish(object):
    """
    Init : initialise les variables de ThreeFish
    La clé principale est générée, découpées en mots de 64 bits, les tweaks sont déduits de celle-ci,
    et les clés de tournées sont calculées (20 clés à utiliser toutes les 4 tournées)
    """
    def __init__(self, blsz, mode, key=None):
        self.blocksize = blsz
        self.mode = mode
        self.round_keys = None
        self.master_key = None
        self.master_key_size = None
        self.tweak = None

        # Vecteur d'initialisation
        if (mode == "CBC" and not key):
            self.IV = splitBytesInWords(self.generateKey(), int(self.blocksize/8))

        # Master key (clé originale)
        if (not key or len(key) != int(blsz/8)):
            key = self.generateKey()
        print("Clé originale : " + str(key))
        print("Clé de " + str(len(key)) + " bytes. (" + str(len(key)*8) + " bits)")
        self.constructKeyAndTweaks(key)
        print("Master Key : " + str(self.master_key))
        print("Mots générés : " + str(len(self.master_key) - 1) + "+1 (sous-clés)")

        # Tweaks
        print("Tweaks : " + str(self.tweak))

        # Clés de tournées
        self.generateRoundKeys()
        print("Clés de tournées générées. (" + str(len(self.round_keys)) + ")")
        print("Clés de tournées : " + str(self.round_keys))

    """
    Retourne la clé (master key) au format hexadecimal
    """
    def getBinaryMasterKey(self):
        return binascii.hexlify(joinWordsToBytes(self.master_key[:len(self.master_key)-1]))

    """
    Retourne le vecteur d'initialisation au format hexadecimal
    """
    def getBinaryIV(self):
        return binascii.hexlify(joinWordsToBytes(self.IV))

    """
    Génère une clé de la même taille que les blocs à chiffrer (choisie par l'utilisateur)
    """
    def generateKey(self):
        return os.urandom(int(self.blocksize / 8))

    """
    Transforme la clé en plusieurs morceaux, et en déduit les tweaks
    """
    def constructKeyAndTweaks(self, key):
        # création de la clé : découpage et extension
        self.master_key = splitBytesInWords(key, int(self.blocksize/8))
        self.master_key_size = len(self.master_key)
        final_word = functools.reduce(xor, self.master_key) ^ np.uint64(0x1BD11BDAA9FC1A22)
        self.master_key.resize(self.master_key_size+1)
        self.master_key[-1] = np.uint64(final_word)

        # génération (déduction) des tweaks
        self.tweak = [self.master_key[2], self.master_key[1]]
        self.tweak.append(self.tweak[0] ^ self.tweak[1])

    """
    Calcule les clés de tournées (round keys)
    """
    def generateRoundKeys(self):
        list = []
        N = self.master_key_size

        # Génération des 20 clés de tournées
        for i in range(0, 20):
            Kn = []

            # Crée chaque mot pour la clé de tournée
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

        # Transforme la liste des clés de tournées en array
        self.round_keys = np.array(list)

    """
    Effectue un XOR entre chaque partie du bloc et chaque mot correspondant de la clé fournie
    """
    def xorBlockWithKey(self, words, key):
        result = []
        for i in range(0, len(key)):
            result.append(np.uint64(words[i] ^ key[i]))
        return np.array(result, dtype=np.uint64)

    """
    Chiffre un bloc de la taille choisie à la création de l'objet ThreeFish
    """
    def encryptBlock(self, plain64):
        state = plain64
        keynb = 0

        # 76 tournées
        for i in range(0, 76):
            # Ajout de la clé toutes les 4 tournées
            if (i % 4 == 0):
                state = self.xorBlockWithKey(state, self.round_keys[keynb])
                keynb += 1

            # Substitution
            for k in range(0, len(state)-1, 2):
                m1 = state[k]
                m2 = state[k+1]
                state[k] = addIn64bits(m1, m2)
                state[k+1] = state[k] ^ rotateLeft64bits(m2, 12)

            # Permutation : l'ordre des mots est inversé
            temp = np.copy(state)
            for j in range(0, len(state)):
                state[j] = temp[-j]

        # Ajout final de la clé
        state = self.xorBlockWithKey(state, self.round_keys[19])

        # Retourne le bloc final chiffré
        return state

    """
    Déchiffre un bloc
    """
    def decryptBlock(self, cipher64):
        state = cipher64
        keynb = 19

        # 76 tournées
        for i in range(0, 76):
            # Ajout de la clé toutes les 4 tournées
            if (i % 4 == 0):
                state = self.xorBlockWithKey(state, self.round_keys[keynb])
                keynb -= 1

            # Permutation : l'ordre des mots est inversé
            temp = np.copy(state)
            for j in range(0, len(state)):
                state[j] = temp[-j]

            # Substitution
            for k in range(0, len(state)-1, 2):
                m1p = state[k]
                m2p = state[k+1]
                state[k+1] = rotateRight64bits(m2p ^ m1p, 12)
                state[k] = subIn64bits(m1p, state[k+1])

        # Ajout final de la clé (1ere clé de tournée)
        state = self.xorBlockWithKey(state, self.round_keys[0])

        # Retourne le bloc final déchiffré
        return state