from cramershoup import cramershoup_utils as cs

def run():
    print("\n# Déchiffrement...\n")
    message = cs.CramerShoup().decrypt()

    print("Message déchiffré avec la clé privée :")
    print(message)