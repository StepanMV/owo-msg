from .basic_encryptor import Encryptor
import random

class ElGamalEncryptor(Encryptor):
    def __str__(self) -> str:
        return f"ElGamal {self.publicKey[0]} {self.publicKey[1]} {self.publicKey[2]}"

    def __init__(self, keyData=[]):
        super().__init__()
        if not keyData: # если не переданы данные о ключе (генерация ключа)
            self.publicKey.append(self.getRandomPrime())  # p
            self.publicKey.append(self.primitiveRoot(self.publicKey[0]))  # g
            self.privateKey.append(random.randint(1, self.publicKey[0] - 1))  # x
            self.publicKey.append(self.reminderPower(self.publicKey[1], self.privateKey[0], self.publicKey[0]))  # y
        else: # если переданы данные о ключе
            if len(keyData) != 2:
                raise ValueError("ElGamal requires a prime number and a number smaller than it")
            if not self.isPrime(keyData[0]):
                raise ValueError("ElGamal: p is not a prime")
            if keyData[1] >= keyData[0]:
                raise ValueError("ElGamal: x is not smaller than p")
            self.publicKey.append(keyData[0])  # p
            self.publicKey.append(self.primitiveRoot(keyData[0]))  # g
            self.publicKey.append(self.reminderPower(self.publicKey[1], keyData[1], self.publicKey[0]))  # y
            self.privateKey.append(keyData[1])  # x

    # шифрование происходит по формуле: a = g^k mod p, b = m * y^k mod p
    def encrypt(self, input, publicKey=None):
        if publicKey is None:
            publicKey = self.publicKey
        k = random.randint(1, publicKey[0] - 1)
        res = [self.reminderPower(publicKey[1], k, publicKey[0])] # добавляем a отдельно, так как оно не меняется
        # и затем b для каждого символа
        for i in range(len(input)):
            res.append((self.reminderPower(publicKey[2], k, publicKey[0]) * ord(input[i])) % publicKey[0])
        return res

    # расшифровка происходит по формуле: m = b * a^(p-1-x) mod p
    def decrypt(self, encrypted):
        a = encrypted[0]
        res = ""
        for i in range(1, len(encrypted)):
            res += chr((encrypted[i] * self.reminderPower(a, self.publicKey[0] - 1 - self.privateKey[0], self.publicKey[0])) % self.publicKey[0])
        return res

    # поиск первообразного корня по модулю p
    def primitiveRoot(self, p):
        fact = []
        phi = p - 1
        n = phi
        i = 2
        while i * i <= n:
            if n % i == 0:
                fact.append(i)
                while n % i == 0:
                    n //= i
            i += 1
        if n > 1:
            fact.append(n)
        for res in range(2, p + 1):
            ok = True
            for i in range(len(fact)):
                ok &= self.reminderPower(res, phi // fact[i], p) != 1
            if ok:
                return res
        return -1
