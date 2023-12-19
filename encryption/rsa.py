from .basic_encryptor import Encryptor

class RSAEncryptor(Encryptor):
    def __str__(self) -> str:
        return f"RSA {self.publicKey[0]} {self.publicKey[1]} {0}"

    def __init__(self, keyData = []):
        super().__init__()
        if keyData: # если переданы данные о ключе
            if len(keyData) != 2:
                raise ValueError("RSA requires two prime numbers")
            if keyData[0] == keyData[1]:
                raise ValueError("RSA received two equal prime numbers")
            if not self.isPrime(keyData[0]) or not self.isPrime(keyData[1]):
                raise ValueError("RSA received non-prime number(s)")
        else: # если не переданы данные о ключе (генерация ключа)
            keyData.append(self.getRandomPrime())
            keyData.append(self.getRandomPrime())
            while keyData[0] == keyData[1]:
                keyData[1] = self.getRandomPrime()

        self.publicKey.append(keyData[0] * keyData[1]) # n (произведение двух простых чисел)
        phi = (keyData[0] - 1) * (keyData[1] - 1) # функция Эйлера
        self.publicKey.append(self.getCoprime(phi)) # e (взаимно простое с phi)

        self.privateKey.append(self.euclidInverse(self.publicKey[1], phi)) # d - приватный ключ (обратное к e по модулю phi)

    def encrypt(self, input, publicKey=None):
        if publicKey is None:
            publicKey = self.publicKey

        res = []
        # шифрование происходит по формуле: c = m^e mod n
        for char in input:
            res.append(self.reminderPower(ord(char), publicKey[1], publicKey[0])) 
        return res

    def decrypt(self, encrypted):
        res = ""
        # расшифровка происходит по формуле: m = c^d mod n
        for num in encrypted:
            res += chr(self.reminderPower(num, self.privateKey[0], self.publicKey[0]))
        return res
