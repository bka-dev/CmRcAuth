#!/usr/bin/python3

import socket
import struct
import argparse
import getpass
import concurrent.futures
from sys import exit
from colorama import Fore, Style
from ntlm_auth.ntlm import NtlmContext

def header(__version__):

    log(r"""
   _____             _____                        _    _     
  / ____|           |  __ \          /\          | |  | |    
 | |      _ __ ___  | |__) | ___    /  \   _   _ | |_ | |__  
 | |     | '_ ` _ \ |  _  / / __|  / /\ \ | | | || __|| '_ \ 
 | |____ | | | | | || | \ \| (__  / ____ \| |_| || |_ | | | |
  \_____||_| |_| |_||_|  \_\\___|/_/    \_\\__,_| \__||_| |_|
                                                             
                                                             
Author: @_bka_
Version: {}
    """.format(__version__))

def log_success(msg, end='\n'):
    log(f"[+] {msg}", col_start=Fore.GREEN+Style.BRIGHT, col_end=Style.RESET_ALL)
def log_error(msg, end='\n'):
    log(f"[-] {msg}", col_start=Fore.RED+Style.BRIGHT, col_end=Style.RESET_ALL)
def log_info(msg, end='\n'):
    log(f"[~] {msg}", col_start=Fore.CYAN+Style.BRIGHT, col_end=Style.RESET_ALL)
def log(msg, col_start="", col_end="", end='\n'):
    print(f"{col_start}{msg}{col_end}", end=end)

def connect(args, target):
    # Establish a connection to the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.settimeout(5.0)

    try:
        log_info(f"({target}) Connecting to TCP port")
        sock.connect((target, args.port))
        return sock
    except socket.timeout:
        log_error(f"({target}) Connection timed out. No service is listening or the server is unreachable.")
    except socket.error as e:
        log_error(f"({target}) Socket error occurred: {e}")

    sock.close()
    return None

def wait_for_handshake(sock, target):
    sock.settimeout(5.0)

    # Going straight into recv, because CmRcService.exe sends a message first.
    try:
        handshake_message = sock.recv(38)
    except socket.timeout:
        log_error(f"({target}) Socket timed out while waiting for handshake.")
        sock.close()
        return 1

    if "START_HANDSHAKE".encode("UTF16")[2:] in handshake_message:
        return 0
    elif "ERROR_EXISTING_S".encode("UTF16")[2:] in handshake_message:
        log_error(f"({target}) A user is already connected. Connection not possible.")
    elif "ERROR_NO_ACTIVE_".encode("UTF16")[2:] in handshake_message:
        log_error(f"({target}) This computer does not allow connections if it's unattended.")
    else:
        log_error(f"({target}) Handshake not found in server message. This service might not be CmRcService: {handshake_message}")
    return 1

def authenticate(sock, username, password, domain=None, workstation=None):

    # Initialize the NTLM context (client-side)
    ntlm_context = NtlmContext(username=username, password=password, domain=domain, workstation=workstation)

    # Step 1: Send NTLM NEGOTIATE message
    negotiate_message = ntlm_context.step()
    send_packet(sock, "NTLMSSP_NEGOTIATE", negotiate_message)

    # Step 2: Receive CHALLENGE message from server
    server_response = receive_packet(sock)

    # Step 3: Send NTLM AUTHENTICATE message
    authenticate_message = ntlm_context.step(server_response)

    # Send the second packet (command + NTLM message)
    send_packet(sock, "NTLMSSP_AUTHENTICATE", authenticate_message)

    # Step 4: Handle server response to AUTHENTICATE message
    final_response = receive_packet(sock)

    return final_response

def send_packet(sock, command, ntlm_message):

    total_length = len(ntlm_message)

    # Create a packet: length field (4 bytes) + length field (2 bytes) + NTLMSSP message
    packet = struct.pack('<I', len(ntlm_message) + 2) + struct.pack('<H', len(ntlm_message)) + ntlm_message

    # Send the packet to the server
    sock.sendall(packet)

# Function to receive data from the server (assuming similar structure)
def receive_packet(sock):
    # First, read the length field (4 bytes)
    length_bytes = sock.recv(4)
    if not length_bytes:
        raise ConnectionError("Server disconnected.")

    # Unpack the length (network byte order)
    total_length = struct.unpack('<I', length_bytes)[0]

    # Read the main part of the packet (NTLM message)
    data = sock.recv(total_length)

    return data[2:]

def do_access_check(args, target):
    # Connect to target
    sock = connect(args, target)
    if sock is None:
        return 1

    log_info(f"({target}) Connected to TCP port. Waiting for CmRcService.exe handshake")

    # Wait for handshake message to check if CmRcService is present
    result = wait_for_handshake(sock, target)
    if result == 1:
        sock.close
        return 1

    try:
        log_info(f"({target}) Handshake from Remote Control Service detected. Starting authentication flow ...")
        # Do authentication
        final_response = authenticate(sock, username=args.username, password=args.password, domain=args.domain, workstation=args.workstation)
        if "ERROR_LOGON_DENIED".encode('UTF16')[2:] in final_response:
            log_error(f"({target}) Logon not successful (invalid credentials?)")
        elif "ERROR_ACCESS_DENIED".encode('UTF16')[2:] in final_response:
            log_error(f"({target}) Access denied - Credentials correct, but user {args.username} might not be authorized for remote control")
        elif len(final_response) == 60:
            log_success(f"({target}) Logon successful!")

    finally:
        # Close the socket connection
        sock.close()

def main():

    __version__ = "1.0.0"

    header(__version__)

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', dest='username', required=True, help='Username for authentication.')
    parser.add_argument('-p', '--password', dest='password', required=False, help='Password for authentication. Leave empty to let the script ask you.')
    parser.add_argument('-d', '--domain', dest='domain', required=False, help='Domain name for authentication.')
    parser.add_argument('-w', '--workstation', dest='workstation', required=False, help='Name of own workstation.')
    parser.add_argument('-t', '--threads', dest='max_threads', required=False, type=int, default=1, help='Amount of concurrent threads. Default 1.')
    parser.add_argument('--port', dest='port', required=False, default=2701, help='Port to connect to. Defaults to 2701')
    parser_group = parser.add_mutually_exclusive_group(required=True)
    parser_group.add_argument('-i', '--ip', dest='host', help='Host to connect to.')
    parser_group.add_argument('-f', '--file', dest='hosts_file', help='Input file containing hosts.')

    args = parser.parse_args()

    # Ask for password
    if not args.password:
        args.password = getpass.getpass("Password: ")

    # Populate targets list, either from file or from specified address
    if args.host:
        targets = [args.host]
    elif args.hosts_file:
        try:
            with open(args.hosts_file, 'r') as file:
                targets = (file.read()).split("\n")
        except FileNotFoundError as e:
            log_error(f"Error while opening file {args.hosts_file}. Not found")
            exit(1)
        except PermissionError as e:
            log_error(f"Error while opening file {args.hosts_file}. Permission denied.")
            exit(1)
        except IsADirectoryError as e:
            log_error(f"Error while opening file {args.hosts_file}. Is a directory.")
            exit(1)
        except:
            log_error(f"Error while opening file {args.hosts_file}")
            exit(1)

    # Use ThreadPoolExecutor to manage the threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_threads) as executor:
        # Submit each task to the thread pool
        futures = [executor.submit(do_access_check, args, target) for target in targets]

        # Wait for all tasks to complete
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log_error(f"An error occurred: {e}")

if __name__ == '__main__':
    main()
