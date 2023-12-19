import random
import math

class Encryptor:
    def __init__(self):
        self.publicKey = []  # Initialize publicKey as needed
        self.privateKey = []  # Initialize privateKey as needed

    def getPublicKey(self):
        return self.publicKey

    def getRandomNumber(self, min, max):
        return random.randint(min, max)

    def getRandomPrime(self):
        return 3  # Replace with actual prime number generation logic 

    # def reminderPower(self, base, power, mod):
    #     if power > mod:
    #         power %= mod - 1
    #     res = 1
    #     for i in range(power):
    #         res *= base
    #         res %= mod
    #     return res

    def reminderPower(self, base, power, mod):
        base %= mod
        if power > mod: power %= mod - 1
        result = 1
        while power > 0:
            if power % 2 == 1:
                result = (result * base) % mod
            base = (base * base) % mod
            power //= 2
        return result

    def euclidInverse(self, a, m):
        m0 = m
        x0, x1 = 0, 1
        if m == 1:
            return 0
        while a > 1:
            q = a // m
            t = m
            m = a % m
            a = t
            t = x0
            x0 = x1 - q * x0
            x1 = t
        if x1 < 0:
            x1 += m0
        return x1

    def euclidExtended(self, a, b):
        if b == 0:
            return 1, 0
        else:
            x, y = self.euclidExtended(b, a % b)
            return y, x - y * (a // b)

    def getGCD(self, a, b):
        if b == 0:
            return a
        return self.getGCD(b, a % b)

    def getCoprime(self, a):
        for i in range(a - 1, 1, -1):
            if self.getGCD(a, i) == 1:
                return i
        return 1

    def isPrime(self, a):
        b = int(math.sqrt(a))
        for i in range(2, b + 1):
            if a % i == 0:
                return False
        return True

    def encrypt(self, input, publicKey=None):
        raise NotImplementedError("Encryptor.encrypt() not implemented")
    
    def decrypt(self, encrypted):
        raise NotImplementedError("Encryptor.decrypt() not implemented")
