import asyncio
from connection import *
import sys
import aioconsole

server = Server(ip=sys.argv[1], port=int(sys.argv[2]))

async def main():
    server.listen()
    while True:
        line = await aioconsole.ainput()
        if line == "EXIT":
            break


asyncio.run(main())