from .basic_encryptor import Encryptor
import random

class ElGamalEncryptor(Encryptor):
    def __str__(self) -> str:
        return f"ElGamal {self.publicKey[0]} {self.publicKey[1]} {self.publicKey[2]}"

    def __init__(self, publicKeyData=None):
        super().__init__()
        if publicKeyData is None:
            self.publicKey.append(self.getRandomPrime())  # p
            self.publicKey.append(self.primitiveRoot(self.publicKey[0]))  # g
            self.privateKey.append(random.randint(1, self.publicKey[0] - 1))  # x
            self.publicKey.append(self.reminderPower(self.publicKey[1], self.privateKey[0], self.publicKey[0]))  # y
        else:
            if len(publicKeyData) != 2:
                raise ValueError("ElGamal requires a prime number and a number smaller than it")
            if not self.isPrime(publicKeyData[0]):
                raise ValueError("ElGamal: p is not a prime")
            if publicKeyData[1] >= publicKeyData[0]:
                raise ValueError("ElGamal: x is not smaller than p")
            self.publicKey.append(publicKeyData[0])  # p
            self.publicKey.append(self.primitiveRoot(publicKeyData[0]))  # g
            self.publicKey.append(self.reminderPower(self.publicKey[1], publicKeyData[1], self.publicKey[0]))  # y
            self.privateKey.append(publicKeyData[1])  # x

    def encrypt(self, input, publicKey=None):
        if publicKey is None:
            publicKey = self.publicKey
        k = random.randint(1, publicKey[0] - 1)
        res = [self.reminderPower(publicKey[1], k, publicKey[0])]
        for i in range(len(input)):
            res.append((self.reminderPower(publicKey[2], k, publicKey[0]) * ord(input[i])) % publicKey[0])
        return res

    def decrypt(self, encrypted):
        a = encrypted[0]
        res = ""
        for i in range(1, len(encrypted)):
            res += chr((encrypted[i] * self.reminderPower(a, self.publicKey[0] - 1 - self.privateKey[0], self.publicKey[0])) % self.publicKey[0])
        return res

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
