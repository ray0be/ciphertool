import sys
import functions as g
from threefish import threefish_utils as tf

def run():
    default_file = "files/annechatte.png"
    #filename = g.chooseFilename("Choose file to encrypt", default_file)
    filename = default_file

    print("\n# File opening\n")
    print("File to encrypt : ", filename)

    with open(filename, "rb") as f:
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
            print("Les blocs sont de " + str(blocksize) + " bits")
        else:
            sys.exit("Vous devez entrer un nombre.")

        """
        Découpage du fichier en blocs de taille spécifiée
        """
        chunks = g.chunk_file(f, int(blocksize/8))
        nb_bytes = 0
        for bytes in chunks:
            for byte in bytes:
                nb_bytes += 1

        print("File content : " + str(nb_bytes) + " bytes")

        """
        Préparation de l'algorithme ThreeFish (génération des clés...)
        """
        print("\n# ThreeFish start\n")
        threefish = tf.ThreeFish(chunks, 512)

        """
        Chiffrement du fichier
        """
        print("\n# Encrypting file...\n")

        #...