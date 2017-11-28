import os

from threefish import threefish_encrypt
from threefish import threefish_decrypt
from cramershoup import cramershoup_encrypt
from cramershoup import cramershoup_decrypt
from hash import compute_hash
from hash import check_hash

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
        print("Vous avez choisi le chiffrement symétrique ThreeFish.")
        threefish_encrypt.run()

    elif (choice == 2):
        print("Vous avez choisi le déchiffrement ThreeFish.")
        threefish_decrypt.run()

    elif (choice == 3):
        print("Vous avez choisi le chiffrement asymétrique Cramer-Shoup.")
        cramershoup_encrypt.run()

    elif (choice == 4):
        print("Vous avez choisi le déchiffrement de Cramer-Shoup.")
        cramershoup_decrypt.run()

    elif (choice == 5):
        print("Vous avez choisi de créer un hash.")
        compute_hash.run()

    elif (choice == 6):
        print("Vous avez choisi la vérification d'un hash.")
        check_hash.run()

    else:
        menu()