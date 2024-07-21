import socket
import threading
import random
import string
import argparse
import json
import requests
import time
from typing import List, Tuple, Dict
from datetime import datetime

def generate_secret(length: int) -> str:
    chars: str = string.ascii_letters + string.digits + "&!-_%.?$"
    return ''.join(random.choice(chars) for _ in range(length))

def get_public_ip() -> str:
    try:
        response = requests.get('https://api.ipify.org?format=json')
        response.raise_for_status()
        return response.json()['ip']
    except requests.RequestException as e:
        print(f"Error retrieving public IP address: {e}")
        return None

def update_noip_ip(public_ip: str, username: str, password: str, hostname: str):
        try:
            response = requests.get(f'http://{username}:{password}@dynupdate.no-ip.com/nic/update?hostname={hostname}&myip={public_ip}')
            response.raise_for_status()
            print(f"No-IP server response: {response.text.strip()}")
        except requests.RequestException as e:
            print(f"Error updating No-IP: {e}")

def broadcast(message: str, sender_socket: socket.socket, clients: List[Tuple[socket.socket, Tuple[str, int]]]):
    for client_socket, _ in clients:
        if client_socket != sender_socket:
            # Forward command to clients
            client_socket.send(b'Pym.BroadcastMessage.Forward')
            client_socket.send(message.encode('utf-8'))

def create_absolute_address(addresses: Dict[str, Dict[str, str]]) -> Tuple[str, str, str]:
    while True:
        address: str = '@' + ''.join(random.choices(string.ascii_letters + string.digits + '&!-_%.?$', k=20))
        if address not in addresses:
            break

    secret: str = generate_secret(40)
    creation_date: str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Store the unique address
    addresses[address] = {'secret': secret, 'creation_date': creation_date}
    return address, secret, creation_date

def handle_client(client_socket: socket.socket, client_address: Tuple[str, int], clients: List[Tuple[socket.socket, Tuple[str, int]]]):
    addresses: Dict[str, Dict[str, str]] = {} # Dictionary to store client addresses and their properties

    try:
        while True:
            # Wait a client command
            command: str = client_socket.recv(1024).decode('utf-8')
            if command:
                print(f"Received from {client_address} command: {command}")
                if command == 'Pym.BroadcastMessage.Command':
                    message: str = client_socket.recv(1024).decode('utf-8')
                    print(f"Received from {client_address} message to broadcast to all clients: {message}")
                    broadcast(message, client_socket, clients)
                elif command == 'Pym.CreateAbsoluteAddress.Command':
                    address: str
                    secret: str
                    creation_date: str
                    address, secret, creation_date = create_absolute_address(addresses)
                    print(f"Generated absolute address: {address}, secret: {secret}, creation date: {creation_date}")
                    response_data: Dict[str, str] = {
                        'address': address,
                        'secret': secret,
                        'creation_date': creation_date
                    }
                    response = json.dumps(response_data)
                    client_socket.send(b'Pym.CreateAbsoluteAddress.Response')
                    client_socket.send(response.encode('utf-8'))
    except:
        print(f"Client {client_address} disconnected")
        clients.remove((client_socket, client_address))
        client_socket.close()

def dynDNS_periodic_update(dynDNS_username: str, dynDNS_password: str, dynDNS_hostname: str, dynDNS_update_interval: int):
    last_dynDNS_update = ""

    while True:
        public_ip = get_public_ip()
        if public_ip:
            print("As DynDNS configuration is activated, updating NoIP service")
            update_noip_ip(public_ip, dynDNS_username, dynDNS_password, dynDNS_hostname)

        time.sleep(dynDNS_update_interval)

def main():
    Mit_License = """
The MIT License (MIT)
Copyright (c) 2024 pymteam@pymapp.org
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

    clients: List[Tuple[socket.socket, Tuple[str, int]]] = []

    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="PYM Server")
    parser.add_argument('--server_ip', type=str, default='127.0.0.1', help='Server public or local IP address')
    parser.add_argument('--server_port', type=int, default=8080, help='Server port')
    parser.add_argument('--admin_address', type=str, default='@pymadmin', help='Admin absolute address')

    # Optional DynDNS arguments if the server is in a local network with no static public address
    parser.add_argument('--dynDNS_username', type=str, help='DynDNS username')
    parser.add_argument('--dynDNS_password', type=str, help='DynDNS password')
    parser.add_argument('--dynDNS_hostname', type=str, help='DynDNS hostname')
    parser.add_argument('--dynDNS_update_interval', type=int, help='DynDNS update interval in seconds')

    args: argparse.Namespace = parser.parse_args()

    print(Mit_License)

    server_ip: str = args.server_ip
    server_port: str = args.server_port
    admin_address: str = args.admin_address
    admin_secret: str = generate_secret(40)

    print(f"Server is starting at {server_ip}:{server_port}")
    print(f"Admin address: {admin_address}")
    print(f"Admin secret: {admin_secret}")

    # Extract and print DynDNS configuration if provided
    dynDNS_username: str = args.dynDNS_username
    dynDNS_password: str = args.dynDNS_password
    dynDNS_hostname: str = args.dynDNS_hostname
    dynDNS_update_interval: int = args.dynDNS_update_interval

    # Check that we have all the informations, no one missing
    if dynDNS_username and dynDNS_password and dynDNS_hostname and dynDNS_update_interval:
        print(f"DynDNS configuration:")
        print(f"Dynamic DNS username: {dynDNS_username}")
        print(f"Dynamic DNS password: {dynDNS_password}")
        print(f"Dynamic DNS hostname: {dynDNS_hostname}")
        print(f"Dynamic DNS update interval: {dynDNS_update_interval} seconds")
        dynDNS_activated: boolean = True
    else:
        print("DynDNS configuration is not activated")
        dynDNS_activated: boolean = False

    public_ip = get_public_ip()

    if public_ip:
        print(f"Public IP address detected: {public_ip}")
        if dynDNS_activated:
            # Start the dynamic DNS entry periodic update thread
            update_thread = threading.Thread(
                target=dynDNS_periodic_update,
                args=(dynDNS_username, dynDNS_password, dynDNS_hostname, dynDNS_update_interval)
            )
            update_thread.daemon = True  # Ensure the thread exits when the main program does
            update_thread.start()
        else:
            print(f"As DynDNS configuration is not activated, we are not updating NoIP service")
    else:
        print("Failed to retrieve public IP address")

    server: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((server_ip, server_port))
    except OSError as e:
        print(f"Binding failed: {e}")
        return

    server.listen(5)

    print("Server is listening for connections...")
    while True:
        client_socket: socket.socket
        client_address: Tuple[str, int]

        client_socket, client_address = server.accept()
        clients.append((client_socket, client_address))
        print(f"Client {client_address} connected")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address, clients))
        client_handler.start()

if __name__ == "__main__":
    main()
