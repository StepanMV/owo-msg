import encryption
import asyncio
from connection import *
import aioconsole
import sys

if len(sys.argv) not in (4, 6):
    print("Usage: python3 client_main.py <server ip> <server port> <encryptor> [<arg1> <arg2>]")
    exit()

if len(sys.argv) == 6:
    if sys.argv[3] == "RSA":
        encryptor = encryption.RSAEncryptor((int(sys.argv[4]), int(sys.argv[5])))
    elif sys.argv[3] == "Rabin":
        encryptor = encryption.RabinEncryptor((int(sys.argv[4]), int(sys.argv[5])))
    elif sys.argv[3] == "ElGamal":
        encryptor = encryption.ElGamalEncryptor((int(sys.argv[4]), int(sys.argv[5])))
    elif sys.argv[3] == "DifHel":
        encryptor = encryption.DiffieHellmanEncryptor((int(sys.argv[4]), int(sys.argv[5])))
    else:
        print("Encryptor is one of: RSA, Rabin, ElGamal, DifHel")
        exit()

elif len(sys.argv) == 4:
    if sys.argv[3] == "RSA":
        encryptor = encryption.RSAEncryptor()
    elif sys.argv[3] == "Rabin":
        encryptor = encryption.RabinEncryptor()
    elif sys.argv[3] == "ElGamal":
        encryptor = encryption.ElGamalEncryptor()
    elif sys.argv[3] == "DifHel":
        encryptor = encryption.DiffieHellmanEncryptor()
    else:
        print("Encryptor is one of: RSA, Rabin, ElGamal, DifHel")
        exit()



client = Client(server_ip=sys.argv[1], server_port=int(sys.argv[2]), encryptor=encryptor)

async def main():
    client.connect()
    while True:
        line = await aioconsole.ainput()
        client.send(line)
        if line == "EXIT":
            break

asyncio.run(main())