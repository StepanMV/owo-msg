import asyncio
from connection import *
import sys

server = Server(ip=sys.argv[1], port=int(sys.argv[2]))

async def main():
    server.listen()
    while True:
        await asyncio.sleep(0.001)


asyncio.run(main())