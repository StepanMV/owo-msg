import encryption
import asyncio
from connection import *
import aioconsole
import sys

client = Client(server_ip=sys.argv[1], server_port=int(sys.argv[2]), encryptor=encryption.RSAEncryptor((631, 113)))

async def main():
    client.connect()
    while True:
        line = await aioconsole.ainput()
        client.send(line)
        if line == "EXIT":
            break

asyncio.run(main())