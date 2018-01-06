from cramershoup import cramershoup_utils as cs

def run():
    print("\n# Génération des clés publiques et privées\n")
    print("Génération en cours...")

    CS = cs.CramerShoup()
    print(CS.key_generation())

    print("Ces clés ont été enregistrées dans les fichiers \"files/cramershoup_key\" et \"files/cramershoup_key.pub\"")

    print("\n# Choix du message\n")

    msg = input("Message à chiffrer : ")

    print("\n# Chiffrement...\n")
    cipher = CS.encrypt(msg)

    print("Message chiffré avec la clé publique.")
    print("Enregistrement du message chiffré dans le fichier \"files/cramershoup_soupe.txt\".")
    cs.write_list_to_file("files/cramershoup_soupe.txt", cipher)
    print("Tout est fait.")