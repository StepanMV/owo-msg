from .basic_encryptor import Encryptor

class RabinEncryptor(Encryptor):
    def __str__(self) -> str:
        return f"Rabin {self.publicKey[0]} {0} {0}"

    def __init__(self, keyData=[]):
        super().__init__()
        if not keyData: # если не переданы данные о ключе (генерация ключа)
            p = self.getRandomPrime()
            q = self.getRandomPrime()
            while p % 4 != 3:
                p = self.getRandomPrime()
            while p == q or q % 4 != 3:
                q = self.getRandomPrime()
            # приватный ключ - два простых числа p и q
            self.privateKey.append(p)
            self.privateKey.append(q)
            # открытый ключ - их произведение
            self.publicKey.append(self.privateKey[0] * self.privateKey[1])
        else: # если переданы данные о ключе
            if len(keyData) != 2:
                raise ValueError("Invalid Rabin public key data")
            if keyData[0] == keyData[1]:
                raise ValueError("Rabin received two equal prime numbers")
            if not self.isPrime(keyData[0]) or not self.isPrime(keyData[1]):
                raise ValueError("Rabin received non-prime number(s)")
            if keyData[0] % 4 != 3 or keyData[1] % 4 != 3:
                raise ValueError("Rabin received non-prime numbers that are not congruent to 3 modulo 4")
            self.publicKey.append(keyData[0] * keyData[1]) # p * q
            self.privateKey.append(keyData[0]) # p
            self.privateKey.append(keyData[1]) # q

    def encrypt(self, input, publicKey=[]):
        if len(publicKey) == 0:
            publicKey = self.publicKey
        # шифрование происходит по формуле: c = m^2 mod n
        return [self.reminderPower(ord(ch), 2, publicKey[0]) for ch in input]

    def decrypt(self, encrypted):
        p = self.privateKey[0]
        q = self.privateKey[1]
        n = self.publicKey[0]
        decrypted = ""
        # используя китайскую теорему об остатках и расширенный алгоритм Евклида, расшифровываем каждый символ
        # приходится выбирать из 4 вариантов
        for c in encrypted:
            mp = self.reminderPower(c, (p + 1) // 4, p)
            mq = self.reminderPower(c, (q + 1) // 4, q)
            yp, yq = self.euclidExtended(p, q) # нетривиальные нильпотенты
            rootp = yp * p * mq
            rootq = yq * q * mp
            r = (rootp + rootq) % n
            s = (rootp - rootq) % n
            if r < 128:
                decrypted += chr(r)
            elif n - r < 128:
                decrypted += chr(n - r)
            elif s < 128:
                decrypted += chr(s)
            elif n - s < 128:
                decrypted += chr(n - s)
        return decrypted

    # китайская теорема об остатках
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
