import socket
import threading
import random
import string
import argparse
import json
import requests
import time
from typing import Dict, List, Tuple, Dict, Optional 
from datetime import datetime, timedelta

# PYM server version information
pym_server_version = "1.0.0"

# PYM license information (MIT)
pym_license = """
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

# Declare a global dictionary to store clients PYM addresses and their properties
addresses: Dict[str, Dict[str, str]] = {} 

# Dictionary to manage routing table with server IP addresses, ports, connection status, and sockets
routing_table: Dict[Tuple[str, int], Dict[str, Tuple[bool, Optional[socket.socket]]]] = {}

# IP Client list that are connected to the server
clients: List[Tuple[socket.socket, Tuple[str, int]]] = []

# Define a global dict to keep track of broadcasted message IDs to avoid to forward again a broacasted message (infinite loop ...)
broadcasted_message_ids: Dict[str, datetime] = {}

# HTTP Rest API Json codes
def get_response_status(code: int) -> str:
    statuses = {
        200: "200 OK",
        201: "201 Created",
        204: "204 No Content",
        301: "301 Moved Permanently",
        302: "302 Found",
        304: "304 Not Modified",
        400: "400 Bad Request",
        401: "401 Unauthorized",
        403: "403 Forbidden",
        404: "404 Not Found",
        405: "405 Method Not Allowed",
        409: "409 Conflict",
        410: "410 Gone",
        429: "429 Too Many Requests",
        500: "500 Internal Server Error",
        501: "501 Not Implemented",
        502: "502 Bad Gateway",
        503: "503 Service Unavailable",
        504: "504 Gateway Timeout"
    }
    return statuses.get(code, "Unknown Status Code")

# Remove old message IDs from the dictionary based on a 12-hour threshold
def clean_old_message_ids():
    global broadcasted_message_ids

    current_time = datetime.utcnow()
    expiration_time = current_time - timedelta(hours=12)

    # Collect keys to remove
    keys_to_remove = [msg_id for msg_id, timestamp in broadcasted_message_ids.items() if timestamp <= expiration_time]

    # Print the keys to remove or a message if there are none
    if keys_to_remove:
        print(f"Cleaning up old message IDs. Keys to remove: {keys_to_remove}")
    else:
        print("No old message IDs to remove.")

    # Remove outdated keys
    for msg_id in keys_to_remove:
        del broadcasted_message_ids[msg_id]

# Function to generate an authentication random secret string of a given length 
def generate_secret(length: int) -> str:
    chars: str = string.ascii_letters + string.digits + "&!-_%.?$"
    return ''.join(random.choice(chars) for _ in range(length))

# Function to generate a random key string of a given length
def generate_randomkey(length: int) -> str:
    chars: str = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

# Function to generate a unique message ID using the current timestamp and a random key
def generate_message_id() -> str:
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
    secret_part = generate_randomkey(40)
    return f"{timestamp}-{secret_part}"

# Function to extract the timestamp from a message ID
def extract_timestamp_from_message_id(message_id: str) -> datetime:
    """Extract the timestamp from the message ID."""
    timestamp_str = message_id.split('-')[0]  # Extract the timestamp part
    return datetime.strptime(timestamp_str, '%Y%m%d%H%M%S%f')

# Function to extract an IP and port from a JSON structure
def extract_ip_port(ip_port_json: Dict[str, str]) -> Tuple[str, int]:
    # Extract IP and port from the JSON structure
    ip = ip_port_json.get('server_ip')
    port_str = ip_port_json.get('server_port')

    # Ensure that both IP and port are present
    if ip is None or port_str is None:
        print("IP address or port is missing from the JSON structure")
        return None, None
    
    # Convert port to an integer
    port = int(port_str)

    return ip, port

# Function to generate a JSON structure from an IP and port
def create_ip_port_json(server_ip: str, server_port: int) -> str:
    ip_port_dict: Dict[str, str] = {
        'server_ip': server_ip,
        'server_port': str(server_port)  # Convert port to string
    }

    # Convert the dictionary to a JSON string
    json_string: str = json.dumps(ip_port_dict)

    return json_string

# Function to retrieve the public IP address using an external service
def get_public_ip() -> str:
    try:
        response = requests.get('https://api.ipify.org?format=json')
        response.raise_for_status()
        return response.json()['ip']
    except requests.RequestException as e:
        print(f"Error retrieving public IP address: {e}")
        return None

# Function to update the IP address on No-IP using DynDNS credentials
def update_noip_ip(public_ip: str, username: str, password: str, hostname: str) -> bool:
    try:
        response = requests.get(f'http://{username}:{password}@dynupdate.no-ip.com/nic/update?hostname={hostname}&myip={public_ip}')
        response.raise_for_status()
        print(f"No-IP server response: {response.text.strip()}")
        return True
    except requests.RequestException as e:
        print(f"Error updating No-IP: {e}")
        return False

# Function ran in a thread to periodically update the dynamic DNS entry if the public IP changes
def dynDNS_periodic_update(public_ip: str, dynDNS_username: str, dynDNS_password: str, dynDNS_hostname: str, dynDNS_update_interval: int):
    while True:
        print("As DynDNS configuration is activated, updating NoIP service")

        last_public_ip = get_public_ip()

        if public_ip != last_public_ip:
            print(f"IP address has changed, old IP : {public_ip}, new IP : last_public_ip")           
            update_noip_ip(public_ip, dynDNS_username, dynDNS_password, dynDNS_hostname)
            public_ip = last_public_ip
        else:
            print(f"IP address has not changed, IP is : {last_public_ip}")    	

        time.sleep(dynDNS_update_interval)

# Function to add a server to the routing table
def add_server_to_routing_table(server_ip: str, server_port: int) -> bool:
    global routing_table

    server_key = (server_ip, server_port)

    if server_key not in routing_table:
        routing_table[server_key] = {'connected': False, 'socket': None}
        print(f"Server {server_ip}:{server_port} added to routing table")
        return True
    else:
        print(f"Server {server_ip}:{server_port} already in routing table")
        return False

# Function to remove a server from the routing table
def remove_server_from_routing_table(server_ip: str, server_port: int) -> bool:
    global routing_table

    server_key = (server_ip, server_port)

    if server_key in routing_table:
        if routing_table[server_key]['connected']:
            print(f"Server {server_ip}:{server_port} is connected in routing table")
            return False
        del routing_table[server_key]
        print(f"Server {server_ip}:{server_port} removed from routing table")
        return True
    else:
        print(f"Server {server_ip}:{server_port} not found in routing table")
        return False

# Function to remove a server from the clients list (it has been identified now has a server and not a client)
def remove_server_from_clients_table(server_ip: str, server_port: int) -> bool:
    global routing_table
    global clients
    
    server_key = (server_ip, server_port)

    # Check if the server is in the routing table
    if server_key in routing_table:
        # Get the socket file descriptor of the server
        server_socket_fd = routing_table[server_key]['socket'].fileno()
        
        # Filter out clients that have the same IP, port, and socket fd as the server
        original_client_count = len(clients)
        
        clients = [
            (client_socket, (client_ip, client_port))
            for client_socket, (client_ip, client_port) in clients
            if (client_ip, client_port) != server_key and client_socket.fileno() != server_socket_fd
        ]
        
        # Check if we removed any clients
        removed_client_count = original_client_count - len(clients)
        if removed_client_count > 0:
            print(f"Removed {removed_client_count} client(s) from the list because identified now as server(s)")
        else:
            print("No clients were removed")
        
        # Print the updated client table
        print("Updated Client Table Info:")
        for client_socket, (client_ip, client_port) in clients:
            print(f"Client: {client_ip}:{client_port}, Socket: {client_socket} (fd={client_socket.fileno()})")
        
        return True
    else:
        print(f"Server {server_ip}:{server_port} not found in routing table")
        return False

# Function to set the server as connected in the routing table 
def set_server_connected(server_ip: str, server_port: int, client_socket: socket.socket) -> None:
    global routing_table

    server_key = (server_ip, server_port)

    if server_key in routing_table:
        routing_table[server_key]['connected'] = True
        routing_table[server_key]['socket'] = client_socket
        print(f"Server {server_ip}:{server_port} is now marked as connected")
    else:
        print(f"Server {server_ip}:{server_port} not found in routing table")

# Function to retrieve the socket corresponding to the server IP and port from the routing table
def get_socket_from_routing_table(server_ip: str, server_port: int) -> Optional[socket.socket]:
    global routing_table

    server_key = (server_ip, server_port)

    if server_key in routing_table and routing_table[server_key]['connected']:
        return routing_table[server_key]['socket']
    else:
        print(f"No connected socket found for server {server_ip}:{server_port}")
        return None

# Function to establish a socket connection to a server
def connect_to_server(server_ip: str, server_port: int) -> socket.socket:
    attempts: int = 0
    while attempts < 3:
        try:
            client_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_ip, server_port))
            return client_socket
        except:
            attempts += 1
            print(f"Connection attempt {attempts} failed. Retrying in 2 seconds...")
            time.sleep(2)
    return None

# Function to connect to a server defined in the routing table
def connect_to_server_in_routing_table(server_ip: str, server_port: int, force: bool = False) -> bool:
    global routing_table

    server_key = (server_ip, server_port)

    if server_key in routing_table:
        if not routing_table[server_key]['connected'] or force:

            if routing_table[server_key]['connected'] and force:
                print(f"Forcing reconnection to server {server_ip}:{server_port}")
                # Close the existing socket if forcing a reconnection
                try:
                    if routing_table[server_key]['socket']:
                        routing_table[server_key]['socket'].close()
                except Exception as e:
                    print(f"Error closing existing connection: {e}")

            try:
                client_socket: socket.socket = connect_to_server(server_ip, server_port)
                if client_socket is None:
                    routing_table[server_key]['socket'] = None
                    routing_table[server_key]['connected'] = False
                    print("Server is not available. Exiting")
                    return False

                routing_table[server_key]['socket'] = client_socket
                routing_table[server_key]['connected'] = True
                print(f"Connected to server {server_ip}:{server_port}")
                return True
            except Exception as e:
                routing_table[server_key]['socket'] = None
                routing_table[server_key]['connected'] = False
                print(f"Failed to connect to server {server_ip}:{server_port}: {e}")
                return False
        else:
            print(f"Already connected to server {server_ip}:{server_port}")
            return False
    else:
        print(f"Server {server_ip}:{server_port} not found in routing table")
        return False

# Function to disconnect from a server defined in the routing table
def disconnect_from_server_in_routing_table(server_ip: str, server_port: int) -> bool:
    global routing_table

    server_key = (server_ip, server_port)

    if server_key in routing_table:
        if routing_table[server_key]['connected']:
            try:
                client_socket = routing_table[server_key]['socket']
                if client_socket:
                    client_socket.close()
                routing_table[server_key]['socket'] = None
                routing_table[server_key]['connected'] = False
                print(f"Disconnected from server {server_ip}:{server_port}")
                return True
            except Exception as e:
                print(f"Failed to disconnect from server {server_ip}:{server_port}: {e}")
                return False
        else:
            print(f"Not connected to server {server_ip}:{server_port} ")
            return False
    else:
        print(f"Server {server_ip}:{server_port} not found in routing table")
        return False

# Function to attempt sending the message on the socket
def attempt_send_message(sock: socket.socket, message: bytes) -> bool:
    try:
        sock.sendall(message)
        print(f"Message sent to server")
        return True
    except Exception as e:
        print(f"Failed to send message to server: {e}")
        return False

# Function to send a message server to server using the given parameters
def send_message_to_server(server_ip: str, server_port: int, command: str, json_body: Dict[str, str]) -> bool:
    # Retrieve the socket from the routing table
    client_socket = get_socket_from_routing_table(server_ip, server_port)
    
    # Generate a unique message ID
    message_id = generate_message_id()

    # Prepare the message to send
    message_json = json.dumps({
        'message_cmd': command,
        "message_id": message_id,
        "message_bdy": json_body
    })

    # Try sending the message using the existing socket
    if client_socket and attempt_send_message(client_socket, message_json.encode('utf-8')):
        return True

    # If sending fails, attempt to reconnect and resend the message
    print(f"Attempting to reconnect to server {server_ip}:{server_port} and resend the message...")
    if connect_to_server_in_routing_table(server_ip, server_port, True):
        client_socket = get_socket_from_routing_table(server_ip, server_port)
        if client_socket:
            return attempt_send_message(client_socket, message_json.encode('utf-8'))

    print(f"Failed to send message to server {server_ip}:{server_port} after reconnecting")
    return False

# Receive a message from a server using the existing socket
def receive_message_from_server(server_ip: str, server_port: int, buffer_size: int = 1024) -> Optional[Dict[str, str]]:
    # Retrieve the socket from the routing table
    client_socket = get_socket_from_routing_table(server_ip, server_port)
    
    if not client_socket:
        print(f"No socket available for server {server_ip}:{server_port}. Attempting to connect...")
        # Attempt to connect to the server if no socket is available
        if not connect_to_server_in_routing_table(server_ip, server_port, True):
            print(f"Failed to connect to server {server_ip}:{server_port}")
            return None
        client_socket = get_socket_from_routing_table(server_ip, server_port)
    
    try:
        # Receive data from the socket
        received_data = client_socket.recv(buffer_size)
        
        if not received_data:
            print(f"No data received from server {server_ip}:{server_port}. Attempting to connect...")

            # Attempt to connect to the server if no data available
            if not connect_to_server_in_routing_table(server_ip, server_port, True):
                print(f"Failed to connect to server {server_ip}:{server_port}")
                return None

            client_socket = get_socket_from_routing_table(server_ip, server_port)

            try:
                # Receive data from the socket
                received_data = client_socket.recv(buffer_size)
            except Exception as e:
                print(f"Failed to receive or decode message from server {server_ip}:{server_port}: {e}")
                return None

        # Decode the received data and parse it as JSON
        decoded_message = received_data.decode('utf-8')
        json_message = json.loads(decoded_message)
        
        # Return the json with message command, message identifier and message body
        return json_message 

    except Exception as e:
        print(f"Failed to receive or decode message from server {server_ip}:{server_port}: {e}")
        return None

# Function to handle client communication
def handle_client(client_socket: socket.socket, client_address: Tuple[str, int], server_ip: str, server_port: int):
    global addresses
    global clients

    try:
        while True:
            # Wait a client message (JSON structured)
            message_data: str = client_socket.recv(1024).decode('utf-8')

            message_json = json.loads(message_data)

            message_cmd = message_json['message_cmd']
            message_id = message_json['message_id']

            if message_cmd:

                if message_cmd == 'Pym.BroadcastMessage.Command':
                    message_bdy = message_json['message_bdy']
                    print(f"Received from {client_address} message to broadcast to all clients: {message_bdy} with ID: {message_id}")

                     # Broadcast the message to all clients except the message ID
                    broadcast(message_json, client_socket)

                elif message_cmd == 'Pym.BroadcastMessage.ServerForward':
                    message_bdy = message_json['message_bdy']
                    print(f"Received from a federated server a message to broadcast to all clients: {message_bdy} with ID: {message_id}")

                     # Broadcast the message to all clients except the message ID
                    broadcast(message_json, client_socket)

                elif message_cmd == 'Pym.CreateAbsoluteAddress.Command':
                    print(f"Received from {client_address} message create an absolute address with ID: {message_id}")
                    address: str
                    secret: str
                    creation_date: str
                    address, secret, creation_date = create_absolute_address(addresses)
                    print(f"Generated absolute address: {address}, secret: {secret}, creation date: {creation_date}")
                    response_bdy_json: Dict[str, str] = {
                        'address': address,
                        'secret': secret,
                        'creation_date': creation_date
                    }
                    response_bdy = json.dumps(response_bdy_json)

                    # Generate unique message ID
                    response_message_id: str = generate_message_id()
                    
                    response_message_json = json.dumps({
                        'message_cmd': 'Pym.CreateAbsoluteAddress.Response',
                        'message_id': response_message_id,
                        'message_bdy': response_bdy
                    })
        
                    client_socket.sendall(response_message_json.encode('utf-8'))

                elif message_cmd == 'Pym.AttachServer.Command':
                    message_bdy = message_json['message_bdy']
                    message_bdy_json: Dict[str, str]  = json.loads(message_bdy)
                    target_server_ip, target_server_port = extract_ip_port(message_bdy_json)

                    print(
                        f"Received from {client_address} message to attach to a server @: "
                        f"{target_server_ip} port: {target_server_port} with ID: {message_id}"
                    )

                    if add_server_to_routing_table(target_server_ip, target_server_port):
                        client_response_status = get_response_status(200)

                        if connect_to_server_in_routing_table(target_server_ip, target_server_port):
                            if not send_message_to_server(
                                target_server_ip,
                                target_server_port,
                                'Pym.RegisterMeInYourRoutingTable.Command',
                                create_ip_port_json(server_ip, server_port)
                            ):
                                client_response_status = get_response_status(500)
                            else:
                                server_response_json = receive_message_from_server(target_server_ip, target_server_port)
                                if not server_response_json:
                                    client_response_status = get_response_status(500)                             
                                else:
                                    server_response_message_cmd = server_response_json['message_cmd']
                                    server_response_message_id = server_response_json['message_id']
                                    server_response_message_bdy = server_response_json['message_bdy']

                                    if (server_response_message_cmd == 'Pym.RegisterMeInYourRoutingTable.Response' and
                                            server_response_message_bdy == get_response_status(200)):

                                        client_response_status = get_response_status(200)

                                        client_handler = threading.Thread(
                                            target=handle_client,
                                            args=(
                                                get_socket_from_routing_table(target_server_ip, target_server_port),
                                                (target_server_ip, target_server_port),
                                                server_ip,
                                                int(server_port)
                                            )
                                        )

                                        client_handler.start()

                                    else:
                                        client_response_status = get_response_status(500)
                        else:
                            client_response_status = get_response_status(500)

                    else:
                        client_response_status = get_response_status(500)

                    # Generate unique message ID
                    client_response_message_id: str = generate_message_id()
                    
                    client_response_json = json.dumps({
                        'message_cmd': 'Pym.AttachServer.Response',
                        'message_id': client_response_message_id,
                        'message_bdy': client_response_status
                    })
        
                    client_socket.sendall(client_response_json.encode('utf-8'))

                elif message_cmd == 'Pym.DetachServer.Command':
                    message_bdy = message_json['message_bdy']
                    message_bdy_json: Dict[str, str]  = json.loads(message_bdy)
                    target_server_ip, target_server_port = extract_ip_port(message_bdy_json)

                    print(
                        f"Received from {client_address} message to detach from a server @: "
                        f"{target_server_ip} port: {target_server_port} with ID: {message_id}"
                    )

                    if not send_message_to_server(
                                target_server_ip,
                                target_server_port,
                                'Pym.UnregisterMeFromYourRoutingTable.Command',
                                create_ip_port_json(server_ip, server_port)
                    ):
                        client_response_status = get_response_status(500)
                    else:
                        server_response_json = receive_message_from_server(target_server_ip, target_server_port)
                        if not server_response_json:
                            client_response_status = get_response_status(500)                             
                        else:
                            server_response_message_cmd = server_response_json['message_cmd']
                            server_response_message_id = server_response_json['message_id']
                            server_response_message_bdy = server_response_json['message_bdy']
                            if (server_response_message_cmd == 'Pym.UnregisterMeFromYourRoutingTable.Response' and
                                server_response_message_bdy == get_response_status(200)):
                                client_response_status = get_response_status(200)
                            else:
                                client_response_status = get_response_status(500)

                    if disconnect_from_server_in_routing_table(target_server_ip, target_server_port):
                        client_response_status = get_response_status(200)

                        if remove_server_from_routing_table(target_server_ip, target_server_port):
                            client_response_status = get_response_status(200)
                        else:
                            client_response_status = get_response_status(500)

                    else:
                        client_response_status = get_response_status(500)


                    # Generate unique message ID
                    client_response_message_id: str = generate_message_id()
                    
                    response_message_json = json.dumps({
                        'message_cmd': 'Pym.DetachServer.Response',
                        'message_id': client_response_message_id,
                        'message_bdy': client_response_status
                    })
        
                    client_socket.sendall(response_message_json.encode('utf-8'))

                elif message_cmd == 'Pym.RegisterMeInYourRoutingTable.Command':

                    message_bdy = message_json['message_bdy']
                    response_data: Dict[str, str]  = json.loads(message_bdy)
                    source_server_ip, source_server_port = extract_ip_port(response_data)

                    print(
                        f"Received from {client_address} message to be registered in my routing table: "
                        f"{source_server_ip} port: {source_server_port} with ID: {message_id}"
                    )

                    add_server_to_routing_table(source_server_ip, source_server_port)

                    set_server_connected(source_server_ip, source_server_port, client_socket)

                    remove_server_from_clients_table(source_server_ip, source_server_port)

                    response_message_status = get_response_status(200)

                    # Generate unique message ID
                    response_message_id: str = generate_message_id()
                    
                    response_message_json = json.dumps({
                        'message_cmd': 'Pym.RegisterMeInYourRoutingTable.Response',
                        'message_id': response_message_id,
                        'message_bdy': response_message_status
                    })
        
                    client_socket.sendall(response_message_json.encode('utf-8'))

                elif message_cmd == 'Pym.UnregisterMeFromYourRoutingTable.Command':

                    message_bdy = message_json['message_bdy']
                    response_data: Dict[str, str]  = json.loads(message_bdy)
                    source_server_ip, source_server_port = extract_ip_port(response_data)

                    print(
                        f"Received from {client_address} message to be unregistered from my routing table: "
                        f"{source_server_ip} port: {source_server_port} with ID: {message_id}"
                    )

                    remove_server_from_routing_table(source_server_ip, source_server_port)
                    response_message_status = get_response_status(200)

                    # Generate unique message ID
                    response_message_id: str = generate_message_id()
                    
                    response_message_json = json.dumps({
                        'message_cmd': 'Pym.UnregisterMeFromYourRoutingTable.Response',
                        'message_id': response_message_id,
                        'message_bdy': response_message_status
                    })
        
                    client_socket.sendall(response_message_json.encode('utf-8'))

                else:
                    print(f"Received from {client_address} message unknown command: {message_cmd}")

                    print(f"Client {client_address} disconnected")
                    clients.remove((client_socket, client_address))
                    client_socket.close()

                    break

            else:
                print("No command available from server")

                print(f"Client or Federated server {client_address} disconnected")
                clients.remove((client_socket, client_address))
                client_socket.close()

                break

    except:
        print(f"Client or Federated server {client_address} disconnected")
	# If the client was identified has a server, it was removed from the clients list
        if (client_socket, client_address) in clients:
            clients.remove((client_socket, client_address))
        client_socket.close()
          
def broadcast(message_json: str, sender_socket: socket.socket):
    global routing_table
    global broadcasted_message_ids
    global clients

    # Clean up old message IDs before processing new messages
    clean_old_message_ids()

    # Extract the message identifier and its timestamp
    message_id = message_json['message_id']

    # Extract timestamp from message ID
    message_timestamp = extract_timestamp_from_message_id(message_id)

    # Check if this message has already been broadcasted
    if message_id in broadcasted_message_ids:
        print(f"Message with ID {message_id} has already been broadcasted. Skipping...")
        return

    # Add the message identifier and its timestamp to the dictionary of broadcasted messages
    broadcasted_message_ids[message_id] = message_timestamp

    # Print client table information before broadcasting to clients
    print("Client Table Info:")
    for client_socket, (client_ip, client_port) in clients:
            print(f"Client: {client_ip}:{client_port}, Socket: {client_socket}")

    # Broadcast to all connected clients except the sender ... we keep source message identifier as it's a forward
    for client_socket, (client_ip, client_port) in clients:
        if client_socket != sender_socket:
            try:
                # Forward command to clients
                forwarded_message_json = json.dumps({
                    'message_cmd': 'Pym.BroadcastMessage.ClientForward',
                    'message_id': message_json['message_id'],
                    'message_bdy': message_json['message_bdy']
                })
                print(f"Message broadcasted to client {client_ip}:{client_port} on socket {client_socket.fileno()}")
                client_socket.sendall(forwarded_message_json.encode('utf-8'))
            except Exception as e:
                print(f"Failed to send message to client {client_ip}:{client_port} on socket {client_socket.fileno()}: {e}")

    # Print routing table information before broadcasting to servers
    print("Routing Table Info:")
    for server_key, server_info in routing_table.items():
        ip, port = server_key
        status = "Connected" if server_info['connected'] else "Disconnected"
        socket_info = server_info['socket']
        print(f"Server: {ip}:{port}, Status: {status}, Socket: {socket_info}")

    # Broadcast to all connected servers in the routing table ... we keep source message identifier as it's a forward
    for server_key, server_info in routing_table.items():
        if server_info['connected']:
            server_socket = server_info['socket']
            try:
                # Forward command to servers
                forwarded_message_json = json.dumps({
                    'message_cmd': 'Pym.BroadcastMessage.ServerForward',
                    'message_id': message_json['message_id'],
                    'message_bdy': message_json['message_bdy']
                })
                print(f"Message broadcasted to server {server_key} on socket {server_socket.fileno()}")
                server_socket.sendall(forwarded_message_json.encode('utf-8'))
            except Exception as e:
                print(f"Failed to send message to server {server_key}: {e}")


# Function to create an absolute address, secret, and creation date
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

def main():
    global clients

    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="PYM Server")
    parser.add_argument('--server_ip', type=str, default='127.0.0.1', help='Server public or local IP address')
    parser.add_argument('--server_port', type=int, default=8080, help='Server port')
    parser.add_argument('--admin_address', type=str, default='@pymadmin', help='Admin absolute address')

    # Optional DynDNS arguments if the server is in a local network with no static public address
    parser.add_argument('--dynDNS_username', type=str, help='DynDNS username')
    parser.add_argument('--dynDNS_password', type=str, help='DynDNS password')
    parser.add_argument('--dynDNS_hostname', type=str, help='DynDNS hostname')
    parser.add_argument('--dynDNS_update_interval', type=int, help='DynDNS update interval in seconds')

    # Version flag
    parser.add_argument('--version', action='store_true', help='Show the server software version and exit')

    args: argparse.Namespace = parser.parse_args()

    print(f"Pym server version {pym_server_version}")

    if args.version:
        return

    print(pym_license)

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
                args=(public_ip, dynDNS_username, dynDNS_password, dynDNS_hostname, dynDNS_update_interval)
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
        print(f"Client or Federated server {client_address} connected")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address, server_ip, int(server_port)))
        client_handler.start()

if __name__ == "__main__":
    main()
