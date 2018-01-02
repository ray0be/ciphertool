import os
import re

from threefish import threefish_encrypt
from threefish import threefish_decrypt
from cramershoup import cramershoup_encrypt
from cramershoup import cramershoup_decrypt
from hash import compute_hash
from hash import check_hash
from random import randint, randrange

# Efface la console
def clear():
    os.system('cls' if os.name=='nt' else 'clear')


# Affiche le menu
def menu():
    clear()
    print("Bienvenue dans Ciphertool 1.0\n")

    print("#=========================================#")
    print("# Que voulez-vous faire ?\n")

    print("\t1. Chiffrement symétrique (ThreeFish)")
    print("\t2. DÉchiffrement ThreeFish\n")

    print("\t3. Chiffrement asymétrique (Cramer-Shoup)")
    print("\t4. DÉchiffrement Cramer-Shoup\n")

    print("\t5. Création d'un hash")
    print("\t6. Vérification d'un hash")
    print("#=========================================#\n")

    choice = input("\tVotre choix: ")

    # Conversion en int sécurisée
    try:
        choice = int(choice)
    except Exception:
        menu()

    clear()

    # Détermination du choix de l'utilisateur
    if (choice == 1):
        print("Vous avez choisi le chiffrement symétrique ThreeFish.\n")
        threefish_encrypt.run()

    elif (choice == 2):
        print("Vous avez choisi le déchiffrement ThreeFish.\n")
        threefish_decrypt.run()

    elif (choice == 3):
        print("Vous avez choisi le chiffrement asymétrique Cramer-Shoup.\n")
        cramershoup_encrypt.run()

    elif (choice == 4):
        print("Vous avez choisi le déchiffrement de Cramer-Shoup.\n")
        cramershoup_decrypt.run()

    elif (choice == 5):
        print("Vous avez choisi de créer un hash.\n")
        compute_hash.run()

    elif (choice == 6):
        print("Vous avez choisi la vérification d'un hash.\n")
        check_hash.run()

    else:
        menu()


# Permet de demander une chaine de char
def prompt(text, default):
    value = input(text + " [" + default + "] ")
    if (value == ""):
        return default
    else:
        return value


# Permet de choisir un nom de fichier à lire/écrire
def chooseFilename(text, default):
    print("\n##")

    # Vérifie le nom de fichier
    while True:
        filename = prompt(text, default)

        if re.match('^[a-zA-Z0-9/_.]+$', filename):
            break
        else:
            print("Bad filename. Allowed: a-z A-Z 0-9 _ .")

    print("##\n")
    return filename


# Découpe le fichier en différents blocs de "chunksize" octets
def chunk_file(f, chunksize = 64):
    return iter(lambda: f.read(chunksize), b'')


# Ecrit les bytes dans un fichier
def writeFile(filename, bytes):
    file = open(filename, "wb")
    file.write(bytes)
    file.close()


# Test de primalité Miller-Rabin (test pour estimer si nbr est premier)
# n est le nombre à estimer et k est le nombre de tour à effectuer
def miller_rabin(n, k=20):

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True