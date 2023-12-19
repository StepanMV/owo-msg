from .basic_encryptor import Encryptor

class RSAEncryptor(Encryptor):
    def __str__(self) -> str:
        return f"RSA {self.publicKey[0]} {self.publicKey[1]} {0}"

    def __init__(self, publicKeyData = []):
        super().__init__()
        if publicKeyData: # если переданы данные о ключе
            if len(publicKeyData) != 2:
                raise ValueError("RSA requires two prime numbers")
            if publicKeyData[0] == publicKeyData[1]:
                raise ValueError("RSA received two equal prime numbers")
            if not self.isPrime(publicKeyData[0]) or not self.isPrime(publicKeyData[1]):
                raise ValueError("RSA received non-prime number(s)")
        else: # если не переданы данные о ключе (генерация ключа)
            publicKeyData.append(self.getRandomPrime())
            publicKeyData.append(self.getRandomPrime())
            while publicKeyData[0] == publicKeyData[1]:
                publicKeyData[1] = self.getRandomPrime()

        self.publicKey.append(publicKeyData[0] * publicKeyData[1]) # n (произведение двух простых чисел)
        phi = (publicKeyData[0] - 1) * (publicKeyData[1] - 1) # функция Эйлера
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
