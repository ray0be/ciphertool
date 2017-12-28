import sys
import os
import math
import functions as g
from threefish import threefish_utils as tf

def run():
    default_file = "files/annechatte.png"
    #filename = g.chooseFilename("Choose file to encrypt", default_file)
    filename = default_file

    print("\n# Ouverture du fichier\n")
    print("Fichier à chiffrer : ", filename)

    with open(filename, "rb") as f:
        filesize = os.path.getsize(filename)
        """
        Choix de la taille des blocs
        """
        #blocksize = input("Taille des blocs à utiliser (256/512/1024 bits) : ")
        blocksize = 512
        try:
            blocksize = int(blocksize)
        except Exception:
            sys.exit("Vous devez entrer un nombre.")

        if (blocksize == 256 or blocksize == 512 or blocksize == 1024):
            print("Les blocs sont de " + str(blocksize) + " bits.")
        else:
            sys.exit("Vous devez entrer un nombre.")

        """
        Découpage du fichier en blocs de taille spécifiée
        """
        chunks = g.chunk_file(f, int(blocksize/8))
        print("Taille du fichier : " + str(filesize) + " bytes")
        print("Le fichier est découpé en " + str(math.ceil(filesize / blocksize * 8)) + " blocks.")

        """
        Préparation de l'algorithme ThreeFish (génération des clés...)
        """
        print("\n# Initialisation de ThreeFish\n")
        threefish = tf.ThreeFish(chunks, blocksize)

        """
        Chiffrement du fichier
        """
        print("\n# Chiffrement du fichier\n")

        for bytes in chunks:
            print(bytes)

        #...