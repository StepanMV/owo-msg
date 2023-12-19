import asyncio
import socket
import time
import encryption
import re


class Client:

    def __init__(self, server_ip, server_port=25565, encryptor=encryption.RSAEncryptor()):
        self.server_ip = server_ip
        self.server_port = server_port
        self.main_loop = None

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.setblocking(False)

        self.encryptor = encryptor
        self.server_keys = None

    async def _receive_data(self):  # корутина чтения запросов
        while True:
            try:
                request = await self.main_loop.sock_recv(self.client, 2048)  # чтение запроса клиента
                if not request: raise ConnectionResetError

                # print(f'Client: received {repr(request.decode())}')
                await self._process_data(request.decode())

            except ConnectionResetError:  # если клиент отключился, покидается цикл и задача уничтожается
                print(f'Client: connection lost')
                break
    
    async def _process_data(self, data: str):
        if match := re.match(r'^(RSA|Rabin|ElGamal|DH) (\d+) (\d+) (\d+)$', data):
            self.server_keys = (int(match.group(2)), int(match.group(3)), int(match.group(4)))
            if match.group(1) == "DH":
                self.encryptor.finishKeyExchange(self.server_keys[2], p=self.server_keys[0])
                self.server_keys = self.encryptor.publicKey
        else:
            decrypted: str = self.encryptor.decrypt([int(i) for i in data.rstrip().split(" ")])
            if decrypted.startswith("LIST"):
                print("List of users:")
                print(decrypted[5:].replace(" ", "\n"))
            else:
                print(decrypted)
            

    def connect(self):
        self.main_loop = asyncio.get_event_loop()  # получение event loop
        self.main_loop.create_task(self._connect())
    
    async def _connect(self):
        while True:
            try:
                await self.main_loop.sock_connect(self.client, (self.server_ip, self.server_port))
                selfaddr = self.client.getsockname()
                print(f'Client {selfaddr[0]}:{selfaddr[1]} connected to {self.server_ip}:{self.server_port}')
                self.send(f"{self.encryptor}", encrypt=False)
                break
            except ConnectionRefusedError:
                print(f'Error connecting to {self.server_ip}:{self.server_port}, retrying...')
                time.sleep(1)
        self.main_loop.create_task(self._receive_data())

    def send(self, data: str, encrypt = True):
        if encrypt:
            encrypted = self.encryptor.encrypt(data, publicKey=self.server_keys)
            data = ' '.join([str(i) for i in encrypted]) + '\n'
        try:
            self.client.sendall(data.encode())
            # print(f'Client: sent {repr(data)}')
        except BrokenPipeError:  # если подключение было разорвано (сервер выключен)
            print(f'Error sending {repr(data)}, connection with \'{self.server_ip}\' lost')