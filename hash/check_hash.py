import functions as g
from hash import SHA1
import os

def run():
    filename = g.chooseFilename("Vérifier le hash du fichier", "")

    print("\n# Ouverture du fichier\n")
    print("Fichier à hasher : ", filename)

    # Ouverture du fichier à chiffrer
    with open(filename, "rb") as f:
        # infos sur le fichier
        file_name = os.path.splitext(filename)[0]

        # calcul du hash
        content = f.read()
        hash = SHA1.SHA1().hash(content)

        # Demande du hash à comparer a l'utilisateur
        hash_wanted = input("Entrez le hash à comparer : ")

        print("\n# Comparaison des hash\n")

        # vérification du hash
        print("Hash recherché : " + hash_wanted)
        print("Véritable hash : " + hash)
        if (hash == hash_wanted):
            print("Le hash est correct !")
        else:
            print("ATTENTION! Le hash donné est incorrect.")