from .basic_encryptor import Encryptor

class RabinEncryptor(Encryptor):
    def __str__(self) -> str:
        return f"Rabin {self.publicKey[0]} {0} {0}"

    def __init__(self):
        super().__init__()
        p = self.getRandomPrime()
        q = self.getRandomPrime()
        while p % 4 != 3:
            p = self.getRandomPrime()
        while p == q or q % 4 != 3:
            q = self.getRandomPrime()
        self.privateKey.append(p)
        self.privateKey.append(q)
        self.publicKey.append(self.privateKey[0] * self.privateKey[1])

    def __init__(self, publicKeyData=[]):
        super().__init__()
        if len(publicKeyData) != 2:
            raise ValueError("Invalid Rabin public key data")
        if publicKeyData[0] == publicKeyData[1]:
            raise ValueError("Rabin received two equal prime numbers")
        if not self.isPrime(publicKeyData[0]) or not self.isPrime(publicKeyData[1]):
            raise ValueError("Rabin received non-prime number(s)")
        if publicKeyData[0] % 4 != 3 or publicKeyData[1] % 4 != 3:
            raise ValueError("Rabin received non-prime numbers that are not congruent to 3 modulo 4")
        self.publicKey.append(publicKeyData[0] * publicKeyData[1])
        self.privateKey.append(publicKeyData[0])
        self.privateKey.append(publicKeyData[1])

    def encrypt(self, input, publicKey=[]):
        if len(publicKey) == 0:
            publicKey = self.publicKey
        return [self.reminderPower(ord(ch), 2, publicKey[0]) for ch in input]

    def decrypt(self, encrypted):
        p = self.privateKey[0]
        q = self.privateKey[1]
        n = self.publicKey[0]
        decrypted = ""
        for c in encrypted:
            mp = self.chineseMod((p + 1) // 4, c, p)
            mq = self.chineseMod((q + 1) // 4, c, q)
            yp, yq = self.euclidExtended(p, q)
            rootp = yp * p * mq
            rootq = yq * q * mp
            r = (rootp + rootq) % n
            if r < 128:
                decrypted += chr(r)
            elif n - r < 128:
                decrypted += chr(n - r)
            s = (rootp - rootq) % n
            if s < 128:
                decrypted += chr(s)
            elif n - s < 128:
                decrypted += chr(n - s)
        return decrypted

    def chineseMod(self, k, b, m):
        a = 1
        t = []
        while k > 0:
            t.append(k % 2)
            k = (k - t[-1]) // 2
        for j in range(len(t)):
            if t[j] == 1:
                a = (a * b) % m
                b = (b * b) % m
            else:
                b = (b * b) % m
        return a
