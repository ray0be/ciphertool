import sys
import os
import math
import functions as g
from threefish import threefish_utils as tf

def run():
    default_file = "files/test.png"
    filename = g.chooseFilename("Choose file to encrypt", default_file)

    print("\n# Ouverture du fichier\n")
    print("Fichier à chiffrer : ", filename)

    # Ouverture du fichier à chiffrer
    with open(filename, "rb") as f:
        # Informations sur le fichier
        file_name = os.path.splitext(filename)[0]
        file_ext = os.path.splitext(filename)[1]
        filesize = os.path.getsize(filename)

        """
        Choix de la taille des blocs
        """
        blocksize = input("Taille des blocs à utiliser (256/512/1024 bits) : ")

        # Verification de la taille de blocs choisis
        try:
            blocksize = int(blocksize)
        except Exception:
            sys.exit("Vous devez entrer un nombre.")

        if (blocksize != 256 and blocksize != 512 and blocksize != 1024):
            sys.exit("Vous devez entrer un nombre.")

        """
        Choix du mode de chiffrement
        """
        mode = input("Mode de chiffrement (ECB/CBC) : ")
        mode = mode.upper()
        if (mode != 'CBC'):
            mode = "ECB"
            print("Le mode choisi est ECB.")
        else:
            print("Le mode choisi est CBC.")

        """
        Découpage du fichier en blocs de taille spécifiée
        """
        chunks = g.chunk_file(f, int(blocksize/8))
        print("Les blocs sont de " + str(blocksize) + " bits.")
        print("Taille du fichier : " + str(filesize) + " bytes")
        print("Le fichier est découpé en " + str(math.ceil(filesize / blocksize * 8)) + " blocks.")

        """
        Préparation de l'algorithme ThreeFish (génération des clés...)
        """
        print("\n# Initialisation de ThreeFish\n")
        threefish = tf.ThreeFish(blocksize, mode)

        """
        Chiffrement du fichier
        """
        print("\n# Chiffrement du fichier\n")
        print("Chiffrement en cours...")
        cipher = b""

        if mode == 'CBC':
            # Mode CBC pour le chiffrement
            last_cipher_block = threefish.IV

            for chunk in chunks:
                # bloc à chiffrer
                plain64 = tf.splitBytesInWords(chunk, int(blocksize / 8))

                # Xor avec le chiffré du bloc précédent
                xored64 = threefish.xorBlockWithKey(plain64, last_cipher_block)

                # Chiffrement du bloc
                cipher64 = threefish.encryptBlock(xored64)
                last_cipher_block = cipher64
                cipher += tf.joinWordsToBytes(cipher64)

        else:
            # Mode ECB pour le chiffrement
            for chunk in chunks:
                # Chiffrement de chaque bloc
                plain64 = tf.splitBytesInWords(chunk, int(blocksize/8))
                cipher64 = threefish.encryptBlock(plain64)
                cipher += tf.joinWordsToBytes(cipher64)

        print("Terminé.")

        """
        Ecriture du cipher dans un fichier
        """
        print("\n# Ecriture du fichier (chiffré)\n")

        # Enregistrement du cipher dans le nouveau fichier
        newfilename = file_name + "_encrypted-" + mode + "-" + str(blocksize) + file_ext
        g.writeFile(newfilename, cipher)

        print("Le fichier chiffré a été enregistré : " + newfilename)
        print("Clé de (dé)chiffrement (" + str(blocksize) + " bits) : " + str(threefish.getBinaryMasterKey()))

        if (mode == "CBC"):
            print("Vecteur d'initialisation : " + str(threefish.getBinaryIV()))