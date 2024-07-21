import socket
import threading
import argparse
import time
import json
import queue
from typing import Dict, Tuple

# Declare the global variable
new_client_socket: socket.socket = None
end_process: bool = False
fifo_queue: queue.Queue[str] = queue.Queue()

def receive_messages(client_socket, server_ip, server_port):
    global new_client_socket  # Declare that we are using the global variable to modify it
    global end_process  # Declare that we are using the global variable to modify it
    while True:
        try:
            command: str = client_socket.recv(1024).decode('utf-8')
            if command:
                #print(f"Received from server command: {command}")
                if command == 'Pym.BroadcastMessage.Forward':
                    message: str = client_socket.recv(1024).decode('utf-8')
                    print(f"Received from server broadcasted message: {message}")
                elif command == 'Pym.CreateAbsoluteAddress.Response':
                    response: str = client_socket.recv(1024).decode('utf-8')
                    write_to_fifo(command)
                    write_to_fifo(response)
                else:
                    print(f"Received unknown command from server: {command}")
        except:
            if end_process is not True:
                print("\nDisconnected from server, trying to reconnect")
                while True:
                    client_socket: socket.socket  = connect_to_server(server_ip, server_port)
                    if client_socket is None:
                        print("Server is not reachable (we tried 3 connections), retrying to reconnect")
                    else:
                        print("Reconnected to the server")
                        new_client_socket = client_socket  # Communicate the new socket to the main
                        break
            else:
                break
    return None

def write_to_fifo(message: str):
    global fifo_queue
    # Write a message in the queue
    fifo_queue.put(message)
    #print(f"Message written to FIFO: {message}")

def read_from_fifo() -> str:
    global fifo_queue
    # Read a message in the queue
    message = fifo_queue.get()
    #print(f"Message read from FIFO: {message}")
    return message

def connect_to_server(server_ip: str, server_port: str) -> socket.socket:
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

def create_absolute_address(client_socket: socket.socket) -> Dict[str, str]:
    try:
        # Send address creation command
        client_socket.send(b'Pym.CreateAbsoluteAddress.Command')

        # Read command identifier
        command: str = read_from_fifo()
        # Read command response
        response: str = read_from_fifo()

        if command != 'Pym.CreateAbsoluteAddress.Response':
            print(f"Received unknown command from server: {command}")
            print(f"Received unknown response from server: {response}")
            return None

        response_data: Dict[str, str]  = json.loads(response)
        address: str = response_data.get('address')
        secret: str = response_data.get('secret')
        creation_date: str = response_data.get('creation_date')

        display_address(address=address, secret=secret, creation_date=creation_date, libelle="Generated absolute address")

        return response_data

    except (json.JSONDecodeError) as e:
        # Manage JSON data error
        print("Received non-JSON message: ", response)
        return None

    except (OSError, IOError) as e:
        # Manage network errors
        print(f'Network error: {e}')
        return None

    except Exception as e:
        # Other potential errors
        print(f'An unexpected error occurred: {e}')
        return None

def broadcast_message(client_socket: socket.socket) -> str:
    try:
        # Input message to broadcast
        message: str = input("Enter message: ")

        # Send the command identifier to the server
        client_socket.send(b'Pym.BroadcastMessage.Command')

        # Send command body
        client_socket.send(message.encode('utf-8'))

        return 'Success'

    except (OSError, IOError) as e:
        # Manage network errors
        print(f'Network error: {e}')
        return None

    except Exception as e:
        # Other potential errors
        print(f'An unexpected error occurred: {e}')
        return None

def display_chain(chaine_car: str, max_display: int = 40):
    max_length = max_display - 4
    # Truncate string if it exceeds max_length
    if len(chaine_car) > max_length:
        chaine_car = chaine_car[:max_length]

    # Calculate the number of hyphens
    tirets = '-' * (max_display - 3 - len(chaine_car))

    # Show string with hyphens
    print(f"- {chaine_car} {tirets}")

def display_address(address: str, secret: str, creation_date: str,libelle: str ="", index: str = ""):
    max_display: int = 50

    print("-" * max_display)
    if libelle:
        display_chain(libelle, max_display)
    if index:
        print(f"Index: {index}")
    print(f"Address: {address}")
    print(f"Secret: {secret}")
    print(f"Creation Date: {creation_date}")
    print("-" * max_display)

def display_addresses(addresses: Dict[str, Dict[str, str]], display_index: bool = False, current_address: str = ""):
    if not addresses:
        print("No absolute addresses available")
        return

    print("Displaying all absolute addresses:")
    for index, (address, details) in enumerate(addresses.items(), start=1):
        secret = details.get('secret')
        creation_date = details.get('creation_date')

        if address == current_address:
            libelle = "Current absolute address"
        else:
            libelle = "Other absolute address"

        if display_index:
            display_address(address, secret, creation_date, libelle, f"{index}")
        else:
            display_address(address=address, secret=secret, creation_date=creation_date, libelle=libelle)

def change_current_address(current_address: str, addresses: Dict[str, Dict[str, str]]) -> Tuple[str, str, str]:
    display_addresses(addresses, True, current_address)

    if not addresses:
        print("No addresses to select from")
        return

    try:
        address_index_to_select = int(input("Enter the index of the address you want to set as current: ").strip())
    except ValueError:
        print("Invalid input. Please enter a valid index")
        return None

    if 1 <= address_index_to_select <= len(addresses):
        address_to_select = list(addresses.keys())[address_index_to_select - 1]
        details = addresses[address_to_select]
        address: str = address_to_select
        secret: str = details.get('secret')
        creation_date: str = details.get('creation_date')

        display_address(address=address, secret=secret, creation_date=creation_date, libelle="New current absolute address")

        return address, secret, creation_date
    else:
        print(f"Invalid index {address_index_to_select}. Please select a valid index from the list")
        return None

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
    global new_client_socket  # Declare that we are using the global variable to modify it
    global end_process # Declare that we are using the global variable to modify it

    absolute_address: str = None
    absolute_address_secret: str = None
    absolute_address_creation_date: str = None

    addresses: Dict[str, Dict[str, str]] = {} # Dictionary to store client addresses and their properties

    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="PYM Client")
    parser.add_argument('--server_ip', type=str, default='127.0.0.1', help='Server IP address')
    parser.add_argument('--server_port', type=int, default=8080, help='Server port')

    args: argparse.Namespace = parser.parse_args()

    print(Mit_License)

    server_ip: str = args.server_ip
    server_port: str = args.server_port

    client_socket: socket.socket = connect_to_server(server_ip, server_port)
    if client_socket is None:
        print("Server is not available. Exiting")
        return

    print("Connected to the server")

    receive_thread: threading.Thread = threading.Thread(target=receive_messages, args=(client_socket, server_ip, server_port,))
    receive_thread.start()

    while True:
        print("\nCommands:")
        print("1. Create a new absolute address")
        print("2. Display current absolute address")
        print("3. List absolute addresses")
        print("4. Change current absolute addresses")
        print("5. Broadcast a message")
        print("6. Exit")

        choice: str = input("PYM:> ")

        if new_client_socket is not None:  # Receiving thread has connected to a new socket
            client_socket: socket.socket = new_client_socket
            new_client_socket = None

        if choice == '1':
            call_result: Dict[str, str] = create_absolute_address(client_socket)
            if call_result is None:
                print("Absolute address creation was a failure.")
            else:
                absolute_address = call_result.get('address')
                absolute_address_secret = call_result.get('secret')
                absolute_address_creation_date = call_result.get('creation_date')
                print("Absolute address creation was a success")

                addresses[absolute_address] = {'secret': absolute_address_secret, 'creation_date': absolute_address_creation_date}
        elif choice == '2':
            if absolute_address is not None:
                display_address(address=absolute_address, secret=absolute_address_secret, creation_date=absolute_address_creation_date, libelle="Current absolute address")
            else:
                print(f"Not at least one absolute address created")
        elif choice == '3':
            if absolute_address is not None:
                display_addresses(addresses=addresses, current_address=absolute_address)
            else:
                print(f"Not at least one absolute address created")
        elif choice == '4':
            if absolute_address is not None:
                result = change_current_address(absolute_address, addresses)
                if result:
                    absolute_address, absolute_address_secret, absolute_address_creation_date = result
                    print("Changing current absolute address was a success")
                else:
                    print("Changing current absolute address was a failure")
            else:
                print(f"Not at least one absolute address created")
        elif choice == '5':
            call_result: str = broadcast_message(client_socket)
            if call_result is None:
                print("Message broadcasting was a failure")
            else:
                print("Message broadcasting to all clients was a success")
        elif choice == '6':
            print("Exiting.")
            end_process = True
            client_socket.close()
            return
        else:
            print("Invalid choice, please try again")

if __name__ == "__main__":
    main()
