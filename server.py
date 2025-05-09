# ==========================================================
# Secure UDP Chat Server
# COMPE 560 – Graduate-Level Project
# Author: Kashmira Chavan
# Description:
# - Receives RSA public keys from clients
# - Sends AES key encrypted with RSA
# - Rebroadcasts AES-encrypted messages to other clients
# ==========================================================

import socket
import base64
from crypto_utils import generate_aes_key, encrypt_with_rsa

# Dictionary to store client addresses and AES key
clients = {}            # { addr: aes_key }
rsa_keys = {}           # { addr: rsa_pub_key }
seen_clients = set()    # To prevent rebroadcasting username

# Shared AES key used for all clients (simplified for project scope)
shared_aes_key = generate_aes_key()

# ==========================================================
# Function: handle_messages
# Purpose: Handles incoming UDP messages from clients.
# - If it's a new client, perform RSA-AES key exchange
# - If it's a known client, rebroadcast message to others
# ==========================================================
def log_event(entry):
    """Log a chat event to file."""
    ...

def handle_messages(sock):
    while True:
        data, addr = sock.recvfrom(4096)

        # Case 1: Existing client sending message
        if addr in clients:

            # If this is their first message (likely username), skip rebroadcast
            if addr not in seen_clients:
                seen_clients.add(addr)
                print(f"[Server] Received username from {addr} (not broadcasted)")
                continue

            # Rebroadcast to all other clients
            for client_addr in clients:
                if client_addr != addr:
                    sock.sendto(data, client_addr)

        # Case 2: New client sending RSA public key
        else:
            try:
                # Step 1: Decode RSA public key
                rsa_pub = base64.b64decode(data)

                # Step 2: Encrypt AES key with public key and send it back
                encrypted_key = encrypt_with_rsa(rsa_pub, shared_aes_key)
                sock.sendto(base64.b64encode(encrypted_key), addr)

                # Step 3: Save client's AES key and public key
                clients[addr] = shared_aes_key
                rsa_keys[addr] = rsa_pub

                print(f"[Server] RSA public key received from {addr}")
                print(f"[Server] Encrypted AES key sent to {addr}")

            except Exception as e:
                print(f"[Server] Error during key exchange with {addr}: {e}")

# ==========================================================
# Function: main
# Purpose: Initializes UDP socket and starts message handler
# ==========================================================
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 12345))  # Listen on all interfaces
    print("[Server] Server started on 0.0.0.0:12345\n")
    handle_messages(sock)

# Entry point
if __name__ == "__main__":
    main()
