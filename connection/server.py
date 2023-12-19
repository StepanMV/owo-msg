import asyncio
import socket
import time
import encryption
import re

class Server:

    def __init__(self, ip="127.0.0.1", port=25565):
        self.ip = ip
        self.port = port
        self.main_loop = None

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # создание сокета сервера
        self.server.bind((ip, port))  # назначение сокета на конкретный IP, Port
        self.server.listen(8)  # запуск прослушивания сокета
        self.server.setblocking(False)  # set timeout на 0, необходимо для асинхронности
        self.running = True
        self.client_sockets = {}
        self.client_keys = {}
        self.client_encryptors = {}
        self.client_connections = {}
        self.client_nicknames = {}

        self.rsa = encryption.RSAEncryptor((271, 293))
        self.rabin = encryption.RabinEncryptor((271, 631))
        self.elgamal = encryption.ElGamalEncryptor((293, 271))

    async def _accept_connection(self):  # корутина для принятия подключений
        while self.running:
            print("Server: waiting for connection...")
            client_socket, address = await self.main_loop.sock_accept(self.server)  # ожидание подключения
            address_str = f'{address[0]}:{address[1]}'
            print(f'Server: {address_str} has connected!')
            # для каждого клиента в event loop создаётся задача чтения его запросов
            self.main_loop.create_task(self._receive_data(client_socket))
            self.client_sockets.update({address_str: client_socket})
            self.client_nicknames.update({address_str: address_str})

    async def _receive_data(self, sock: socket.socket):  # корутина чтения запросов
        while self.running:
            address_str = f'{sock.getpeername()[0]}:{sock.getpeername()[1]}'
            try:
                request = await self.main_loop.sock_recv(sock, 2048)  # чтение запроса клиента
                if not request: raise ConnectionResetError

                print(f'Server: received {repr(request.decode())} from {repr(address_str)}')
                await self._process_data(address_str, request.decode())

            except ConnectionResetError:  # если клиент отключился, покидается цикл и задача уничтожается
                print(f'Server: client {repr(address_str)} has disconnected!')
                self.client_sockets.pop(address_str, 0)
                self.client_keys.pop(address_str, 0)
                self.client_encryptors.pop(address_str, 0)
                self.client_connections.pop(address_str, 0)
                self.client_nicknames.pop(address_str, 0)
                break
    
    async def _process_data(self, client, data: str):
        if match := re.match(r'^(RSA|Rabin|ElGamal|DH) (\d+) (\d+) (\d+)$', data):
            self.client_keys[client] = (int(match.group(2)), int(match.group(3)), int(match.group(4)))
            if match.group(1) == "DH":
                self.client_encryptors[client] = encryption.DiffieHellmanEncryptor()
                self.client_encryptors[client].finishKeyExchange(self.client_keys[client][2], p=self.client_keys[client][0])
                self.client_keys[client] = self.client_encryptors[client].publicKey
            elif match.group(1) == "RSA":
                self.client_encryptors[client] = self.rsa
            elif match.group(1) == "Rabin":
                self.client_encryptors[client] = self.rabin
            elif match.group(1) == "ElGamal":
                self.client_encryptors[client] = self.elgamal
            self.send(client, f"{self.client_encryptors[client]}", encrypt=False)
        else:
            decrypted: str = self.client_encryptors[client].decrypt([int(i) for i in data.rstrip().split(" ")])
            print(f'Server: decrypted {repr(decrypted)} from \'{client}\'')
            if decrypted == "LIST":
                
                self.send(client, f"LIST {' '.join([f'{item[0]}({item[1]})' for item in self.client_nicknames.items()])}")
            elif match := re.match(r'^(CONNECT) (\d+.\d+.\d+.\d+:\d+)$', decrypted):
                if match.group(2) not in self.client_sockets:
                    self.send(client, f"ERROR: {match.group(2)} is not connected to the server")
                    return
                if match.group(2) in self.client_connections:
                    self.send(client, f"ERROR: {match.group(2)} is already connected to someone")
                    return
                self.client_connections[client] = match.group(2)
                self.client_connections[match.group(2)] = client
                self.send(client, f"Connected to {match.group(2)}")
                self.send(match.group(2), f"{client} ({self.client_nicknames[client]}) connected to you")
            elif match := re.match(r'^(CONNECT) (.+)$', decrypted): # connect by nickname
                for key, value in self.client_nicknames.items():
                    if value == match.group(2):
                        if key in self.client_connections:
                            self.send(client, f"ERROR: {match.group(2)} is already connected to someone")
                            return
                        self.client_connections[client] = key
                        self.client_connections[key] = client
                        self.send(client, f"Connected to {match.group(2)}")
                        self.send(key, f"{client} ({self.client_nicknames[client]}) connected to you")
                        break
                else:
                    self.send(client, f"ERROR: {match.group(2)} is not connected to the server")
                    return
            elif match := re.match(r'^(DISCONNECT) (\d+.\d+.\d+.\d+:\d+)$', decrypted):
                self.send(client, f"Disconnected from {match.group(2)}")
                self.send(match.group(2), f"{client} ({self.client_nicknames[client]}) disconnected from you")
                self.client_connections.pop(client)
                self.client_connections.pop(match.group(2))
            elif match := re.match(r'^(DISCONNECT) (.+)$', decrypted): # disconnect by nickname
                for key, value in self.client_nicknames.items():
                    if value == match.group(2):
                        self.send(client, f"Disconnected from {match.group(2)}")
                        self.send(key, f"{client} ({self.client_nicknames[client]}) disconnected from you")
                        self.client_connections.pop(client)
                        self.client_connections.pop(key)
                        break
            elif decrypted == "ME":
                self.send(client, f"YOUR IP: {client}")
                self.send(client, f"YOUR NICKNAME: {self.client_nicknames[client]}")
            elif match := re.match(r'^(NICK) (.+)$', decrypted):
                self.client_nicknames[client] = match.group(2)
                if client in self.client_connections:
                    self.send(self.client_connections[client], f"{client} ({self.client_nicknames[client]}) changed nickname to {match.group(2)}")
            else:
                if client in self.client_connections:
                    self.send(self.client_connections[client], f"{self.client_nicknames[client]}: {decrypted}")
            

    def listen(self):
        self.main_loop = asyncio.get_event_loop()  # получение event loop
        self.main_loop.create_task(self._accept_connection())

    def close(self):
        self.running = False
        self.server.close()
    
    def send(self, key, data: str, encrypt = True):
        address_str = f'{self.client_sockets[key].getpeername()[0]}:{self.client_sockets[key].getpeername()[1]}'
        if encrypt:
            encrypted = self.client_encryptors[address_str].encrypt(data, publicKey=self.client_keys[address_str])
            data = ' '.join([str(i) for i in encrypted]) + "\n"
        try:
            self.client_sockets[key].sendall(data.encode())
            print(f'Server: sent {repr(data)} to \'{address_str}\'')
        except BrokenPipeError:  # если подключение было разорвано (сервер выключен)
            print(f'Error sending {repr(data)}, connection with \'{address_str}\' lost')
            self.client_sockets.pop(key, 0)
            self.client_keys.pop(key, 0)
            self.client_encryptors.pop(key, 0)
            self.client_connections.pop(key, 0)
            self.client_nicknames.pop(key, 0)