import functions as g
from hash import SHA1
import os

def run():
    filename = g.chooseFilename("Fichier à hasher", "")

    print("\n# Ouverture du fichier\n")
    print("Fichier à hasher : ", filename)

    # Ouverture du fichier à chiffrer
    with open(filename, "rb") as f:
        # infos sur le fichier
        file_name = os.path.splitext(filename)[0]

        # calcul du hash
        content = f.read()
        hash = SHA1.SHA1().hash(content)

        # enregistrement du hash dans un fichier
        newfilename = file_name + "_hash.txt"
        g.writeFile(newfilename, bytes(hash, encoding='utf8'))

        print("Le hash (" + hash + ") a été écrit dans \"" + newfilename + "\".")