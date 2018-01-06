import math
from random import randint, randrange, getrandbits

import functions as g
from hash import SHA1


def miller_rabin(n, k=20):
# Test de primalité Miller-Rabin (test pour estimer si nbr est premier)
# n est le nombre à estimer et k est le nombre de tour à effectuer
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

def generate_prime_number(length=1025):
    # On va tester si le nombre (p) qu'on va generer est premier avec le test Miller-Rabin
    premier = 4
    while not miller_rabin(premier, 128):
        # On genere un grand entier aleatoire
        hope_prime = getrandbits(length)
        # On le convertit en bit
        hope_prime = bin(hope_prime)
        # On en fait une liste de string
        hope_prime = list(str(hope_prime)[2:]) # On retire les 2 premieres valeurs "0b" qui signialent qu'on est en binaire
        # On complete ou on retire des bits pour que la taille corresponde a celle souhaitee
        if len(hope_prime) < length:  # Si la taille est trop petite
            hope_prime = ['0']*(length-len(hope_prime)) + hope_prime  # On ajoute des '0' devant
        if len(hope_prime) > length:     # Si taille trop grande
            hope_prime = hope_prime[:length]      # On retire des valeurs
        # On met le premier bit à 1 et le dernier à 1 (sinon il est pair eet donc non premier)
        hope_prime[0], hope_prime[len(hope_prime)-1] = '1', '1'
        premier = int(''.join(hope_prime), 2)
        # On rend non friable (p=2*q+1)
        premier = (premier << 1) | 1  # On ajoute un bit a 1 a la fin ce qui revient a faire (*2) et "+1"
    return premier

def create_generator(p, q):
# Permet d'obtenir un generateur
# groupe cyclique d'ordre p
# 2 facteurs premiers : 2 et q = (p-1)/2

    # On genere un entier aleatoire dans Zp
    a = randint(0, p-1)
    # Pour que a soit un generateur il faut a^((p-1)/2) mod p !=1 et a^2 mod p !=1
    while pow(a, (p-1)//2, p) == 1 or pow(a, (p-1)//q, p) == 1:
        a = randint(0, p-1)
    return a

###########################################################################################################################
def add_padding(stream, block_size=1024):
    """
    Ajoute un padding au message afin d'augmenter sa taille à celle désirée '1024 bits)
    """
    stream = bytearray(stream, 'utf8')
    # calcule le nombre de bytes nécessaire au padding
    msb_index = len(str(bin(block_size)[2:]))
    padding_size_bytes = math.ceil(msb_index / 8)
    # calcule la taille du padding
    padding_size = (block_size // 8) - (len(stream) % (block_size//8))
    # ajout des octets aléatoires au message
    for _ in range(0, padding_size - padding_size_bytes):
        stream.append(randint(0, 255))
    # ajoute à la fin du message le nombre de bytes qui ont été ajoutés comme padding
    binary_padding_size = str(bin(padding_size)[2:]).zfill(padding_size_bytes * 8)
    for i in range(padding_size_bytes):
        stream.append(int(binary_padding_size[i*8:(i+1)*8], 2))

    return bytearray(stream)

def write_list_to_file(filename, liste):
    """
    Transforme une liste de valeurs en string pour l'écriture simple dans un fichier
    """
    return g.writeFile(filename, bytes(','.join([str(valeur) for valeur in liste]), encoding='utf8'))

def read_list_from_file(filename):
    """
    Lit le contenu du fichier et extrait la liste des valeurs
    """
    f = open(filename, "r")
    content = f.read()
    f.close()
    return [int(v) for v in content.split(',')]

def read_hex_list_from_file(filename):
    """
    Lit le contenu du fichier (hex numbers) et extrait la liste des valeurs
    """
    f = open(filename, "r")
    content = f.read()
    f.close()
    return content.split(',')
###########################################################################################################################


# Classe cramershoup pour le chiffrement / déchiffrement
class CramerShoup(object):
    @staticmethod
    def key_generation():
    # Permet de generer les clefs : publique et privee

        p = generate_prime_number() # Generation d'un entier premier grand
        alpha1 = create_generator(p, (p-1)//2) # et de deux generateurs
        # On s'assure que les 2 generateurs sont differents
        alpha2 = alpha1
        while alpha2 == alpha1:
            alpha2 = create_generator(p, (p-1)//2)

        # On genere 5 entiers aleatoirement de Zp
        x1 = randint(0, p-1)
        x2 = randint(0, p-1)
        y1 = randint(0, p-1)
        y2 = randint(0, p-1)
        w = randint(0, p-1)

        # On calcule X, Y et W
        X = (pow(alpha1, x1, p) * pow(alpha2, x2, p))
        Y = (pow(alpha1, y1, p) * pow(alpha2, y2, p))
        W = pow(alpha1, w, p)

        # clés publiques et privées
        pub = [p, alpha1, alpha2, X, Y, W]
        priv = [x1, x2, y1, y2, w]

        # Ecriture des clés dans un fichier
        # clé publique
        write_list_to_file('files/cramershoup_key.pub', pub)
        # clé privée
        write_list_to_file('files/cramershoup_key', priv)

        return 'Publique : ' + str(pub) + '\nPrivée : ' + str(priv)

    @staticmethod
    def _hash(b1,b2,c) :
    # Permet d'utiliser la fonction de hashage SHA1
        chat_petit_chat = SHA1.SHA1()
        return chat_petit_chat.hash(str(b1)+str(b2)+str(c))

    @staticmethod
    def encrypt(message):
    # Chiffre le message

        # On prend la clef publique
        p, alpha1, alpha2, X, Y, W = read_list_from_file('files/cramershoup_key.pub')
        # On remboure si besoin le message
        message_tab_completed = add_padding(message)
        # On genere un entier b aleatoire de Zp
        b = randint(0, p-1)
        # On calcule b1 et b2
        B1 = pow(alpha1, b, p)
        B2 = pow(alpha2, b, p)
        # On va chiffrer le message par block
        c = []
        for i in range(0, len(message_tab_completed), 128):  # On prend des blocks de 128 octets
            # On convertit en int ces blocks de 128 octets (byteorder "big" permet de mettre l'octet le plus significatif au debut)
            message_block = int.from_bytes(message_tab_completed[i:i+128], byteorder="big")
            # On calcule c=W(^b)*m
            c.append((pow(W, b, p) * message_block) % p)

        # verification
        x = c[0]
        for i in range(1, len(c)):
            x ^= c[i]
        beta = int(CramerShoup._hash(B1, B2, x), 16) % p
        v = (pow(X, b, p) * pow(Y, b*beta, p)) % p

        # Convertit c en hexa
        for i, block in enumerate(c):
            c[i] = hex(block)[2:]
            # ajoute un padding au bloc chiffré si besoin
            c[i] = '0'*(258 - len(c[i])) + c[i]

        hex_c = ''.join(c)

        # retourne le message chiffré
        return hex(B1), hex(B2), hex_c, hex(v)

    @staticmethod
    def decrypt():
        """
        Déchiffre le message qui a été précédemment chiffré
        """
        # read the private and public keys
        p, _, _, _, _, _ = read_list_from_file('files/cramershoup_key.pub')
        x1, x2, y1, y2, w = read_list_from_file('files/cramershoup_key')
        # read the cipher stream
        b1, b2, c, v = read_hex_list_from_file("files/cramershoup_soupe.txt")
        b1, b2, v = int(b1, 16), int(b2, 16), int(v, 16)
        m = [int(c[i:i+258], 16) for i in range(0, len(c), 258)]
        # verification
        x = m[0]
        for i in range(1, len(m)):
            x ^= m[i]
        beta = int(CramerShoup._hash(b1, b2, x), 16) % p
        v2 = (pow(b1, x1, p) * pow(b2, x2, p) * (pow(pow(b1, y1, p) * pow(b2, y2, p), beta, p))) % p
        if v != v2:
            # Si la verification est fausse
            return "Erreur, les hashs sont differents"

        text = bytearray()
        # On dechiffre chaque block
        for block in m:
            block = (pow(b1, (p-1-w), p) * int(block)) % p
            # calculate the bytes of the original block
            b = bytearray()
            while block:
                b.append(block & 0xff)
                block >>= 8
            text += b[::-1]

        # On enleve le rembourrage qu'on avait mis
        padding_size = int.from_bytes(text[-2:], byteorder="big")
        text = text[:len(text) - padding_size]

        # On renvoit le message dechiffre
        return text.decode('utf-8')