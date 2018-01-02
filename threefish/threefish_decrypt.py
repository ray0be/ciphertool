import sys
import os
import math
import functions as g
import binascii
from threefish import threefish_utils as tf

def run():
    filename = g.chooseFilename("Choose file to decrypt", "")

    print("\n# Ouverture du fichier\n")
    print("Fichier à DÉchiffrer : ", filename)

    # Ouverture du fichier à chiffrer
    with open(filename, "rb") as f:
        # Information sur le fichier
        file_name = os.path.splitext(filename)[0]
        file_ext = os.path.splitext(filename)[1]
        filesize = os.path.getsize(filename)

        """
        Choix de la taille des blocs
        """
        blocksize = input("Taille des blocs à utiliser (256/512/1024 bits) : ")
        try:
            blocksize = int(blocksize)
        except Exception:
            sys.exit("Vous devez entrer un nombre.")

        if (blocksize != 256 and blocksize != 512 and blocksize != 1024):
            sys.exit("Vous devez entrer un nombre.")

        """
        Choix de la clé de déchiffrement
        """
        cle = input("Entrez la clé de déchiffrement : ")
        if (len(cle) != int(blocksize/4)):
            sys.exit("La clé doit être présentée sous format hexadecimal et doit donc faire " + str(int(blocksize/4)) + " caractères.")
        # Conversion de la clé (hexadecimal) en string binaire
        masterkey = binascii.unhexlify(cle)

        """
        Choix du mode de déchiffrement
        """
        mode = input("Mode de DÉchiffrement (ECB/CBC) : ")
        mode = mode.upper()
        IV = None
        if (mode != 'CBC'):
            mode = "ECB"
            print("Le mode choisi est ECB.")
        else:
            print("Le mode choisi est CBC.")

            # Demande du vecteur d'initialisation
            vecinit = input("Entrez le vecteur d'initialisation : ")
            if (len(vecinit) != len(cle)):
                sys.exit("Le vecteur d'initialisation doit être donné sous forme hexadecimale et être aussi long que la clé (" + str(len(cle)) + ")")
            IV = binascii.unhexlify(vecinit)

        """
        Découpage du fichier en blocs de taille spécifiée
        """
        chunks = g.chunk_file(f, int(blocksize/8))
        print("Les blocs sont de " + str(blocksize) + " bits.")
        print("Taille du fichier : " + str(filesize) + " bytes")
        nbblocks = math.ceil(filesize / blocksize * 8)
        print("Le fichier est découpé en " + str(nbblocks) + " blocks.")
        print("Clé de déchiffrement : " + str(masterkey))

        """
        Préparation de l'algorithme ThreeFish (génération des clés...)
        """
        print("\n# Initialisation de ThreeFish\n")
        threefish = tf.ThreeFish(blocksize, mode, masterkey)

        """
        Déchiffrement du fichier
        """
        print("\n# DÉchiffrement du fichier\n")
        print("Déchiffrement en cours...")
        plain = b""

        if mode == 'CBC':
            # Mode CBC pour le déchiffrement
            last_cipher_block = tf.splitBytesInWords(IV, int(blocksize/8))

            for chunk in chunks:
                # bloc à déchiffrer
                cipher64 = tf.splitBytesInWords(chunk, int(blocksize/8))

                # déchiffrement du bloc
                xored64 = threefish.decryptBlock(cipher64)

                # xor avec le chiffré précédent
                plain64 = threefish.xorBlockWithKey(xored64, last_cipher_block)
                last_cipher_block = cipher64
                plain += tf.joinWordsToBytes(plain64)
        else:
            # Mode ECB pour le déchiffrement
            for chunk in chunks:
                # Déchiffrement de chaque bloc
                cipher64 = tf.splitBytesInWords(chunk, int(blocksize/8))
                plain64 = threefish.decryptBlock(cipher64)
                plain += tf.joinWordsToBytes(plain64)

        print("Terminé.")

        """
        Ecriture du clair dans un fichier
        """
        print("\n# Ecriture du fichier (clair / déchiffré)\n")
        newfilename = file_name + "_decrypted" + file_ext
        g.writeFile(newfilename, plain)
        print("Le fichier déchiffré a été enregistré : " + newfilename)