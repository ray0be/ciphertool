class SHA1(object):

    # On initialise l'objet, cad on lui donne des attributs
    def __init__(self):
    #liste de constantes
        self._H = [0x67452301,
                   0xEFCDAB89,
                   0x98BADCFE,
                   0x10325476,
                   0xC3D2E1F0]

    @staticmethod
    def rotl(n, x=1, w=32):
    #Operation de rotatation avec :
    #   n le mot en question
    #   x le nombre de rotation
    #   w la taille max de n ici 32 bits
      return ((n << x) | (n >> w - x))

    @staticmethod
    def _padding(message):
    # Permet de s'assurer que le message (bytearray un tableau d'octets) est d'une taille multiple de 512 bits
    # Pour cela, si besoin :
    #   On ajoute un bit "1" à la fin du message et on complète avec k "0" en laissant 64 bits à la fin
    #   On ecrit sur les 64 derniers bits la taille du message initial

        if len(message) % 64 == 0: # On verifie si la taille du message est un multiple de 512 bits (64 octets)
            return message # Si oui, on garde

        # On convertie la taille du message initial en hexa et on decoupe en une liste de de 8 octets
        initial_message_lenght = [int((hex(len(message)*8)[2:]).rjust(16, '0')[i:i+2], 16)   # rjust permet de tronquer avant la virgule
                           for i in range(0, 16, 2)]

        # On ajoute un bit à "1" (suivie de 7 bits à "0" pour faire un octet)

        message += bytes([0b10000000])

        # On ajoute k bits à "0" mais en conservant les 64 derniers bits pour ecrire la taille initiale du message
        # Pour cela il faut remplir de "0" jusqu'à 448 bits soit 56 octets
        # il faut donc len(stream) + k = 56 % 64

        message += bytes(((56 - len(message)) % 64))
        # On ecrit la taille initiale sur les derniers 64 bits

        message += bytes(initial_message_lenght)

        return message

    @staticmethod
    def _prepare(message):
    # Permet de decoupe le message en block de 64 octets
    # chaque blocks sera ensuite decouper en mots de 4 octets soit 16 mots

        listBlocks = []                 # On initialise la liste de blocks
        nbBlocks = len(message) // 64    # On divise la taille de message en 64 blocks

        for i in range(nbBlocks):       # On parcourt chaque block
            temporary = []              # Stockage temporaire
            for j in range(16):         # Dans chaque block on parcourt chaque mot
                # Calculate the value of the word and append it
                n = 0
                for k in range(4):      # Dans chaque mot on parcourt chaque octet
                    n <<= 8
                    n += message[i*64 + j*4 + k]
                temporary.append(n)
            listBlocks.append(temporary[:])

        return listBlocks

    def _process_block(self, block):
    # Permet le traitement successif sur les blocks de 64 octets (512 bits)

        # On remplit les blocks pour avoir 80 mots/block et non pas 16
        # Il manque donc 64 mots qu'on obtient de la maniere suivante :
        # Rotation appliquée sur le resultat d'un XOR des 4 mots obtenus des iterations precedents
        w = block[:]
        for t in range(16, 80):
            w.append(self.rotl(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]) & 0xffffffff)

        # On initialise 5 variables a,b,c,d et e avec les constantes de "_init_"
        a, b, c, d, e = self._H[:]

        # On parcourt les 80 valeurs
        # Selon le numero de tour, on utilise une fonction parmi 4 fonctions sur 3 des variables
        # On change tout les 20 tours
        for i in range(80):
            if i <= 19:
                f = (b & c) ^ (~b & d)
                k = 0x5a827999
            elif i <= 39:
                f = b ^ c ^ d
                k = 0x6ed9eba1
            elif i <= 59:
                f = (b & c) ^ (b & d) ^ (c & d)
                k = 0x8f1bbcdc
            else:
                f = b ^ c ^ d
                k = 0xca62c1d6

            # A chaque tour on met a jour les variables via des permutation ou des rotations
            T = ((self.rotl(a, 5) + f + e + k + w[i]) & 0xffffffff)
            e = d
            d = c
            c = self.rotl(b, 30) & 0xffffffff
            b = a
            a = T

        # On additionne a la fin le resultat avec le vecteur initial
        self._H[0] = (a + self._H[0]) & 0xffffffff
        self._H[1] = (b + self._H[1]) & 0xffffffff
        self._H[2] = (c + self._H[2]) & 0xffffffff
        self._H[3] = (d + self._H[3]) & 0xffffffff
        self._H[4] = (e + self._H[4]) & 0xffffffff

    def produce_digest(self):
    # Concatene les 5 variables pour en faire le hash de 160 bits (5*32 bits)
        # renvoie 5 blocks de 8 valeurs hexa                             A VERIFIER POUR MODIFICATION
        return ''.join([('%08x' % h) for h in self._H])


    def hash(self, message):
    # Permet de faire le hachage du message

        # Convertion du message en octets
        if isinstance(message, str):
            message = bytes(message, 'utf-8')
        # Decoupage en block
        message = self._prepare(self._padding(message))
        # Traitement sur chaque block
        for block in message:
            self._process_block(block)
        # Production du hash
        return self.produce_digest()
