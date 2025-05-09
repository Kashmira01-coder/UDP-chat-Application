# ==========================================================
# Secure UDP Chat Client (GUI-based)
# COMPE 560 – Graduate-Level Project by Kashmira Chavan
# Features: RSA-AES hybrid encryption, HMAC, ACKs, retransmission
# GUI built using Tkinter
# ==========================================================

import socket
import threading
import base64
import time
import sys
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from crypto_utils import (
    generate_rsa_keypair, decrypt_with_rsa,
    encrypt_with_aes, decrypt_with_aes,
    create_hmac, verify_hmac
)

# === Global Variables ===
aes_key = None
username = None
server_addr = ("localhost", 12345)
pending_acks = {}
msg_counter = 0
received_ids = set()
log_file = "chat_log.txt"
"""
client.py - Secure UDP Chat Client

Handles message sending, GUI, encryption, and retransmission.
"""

def log_event(entry):
    """Log a chat event to file."""
    ...

# === Logging ===
def log_event(entry):
    with open(log_file, "a") as f:
        f.write(f"{time.strftime('%H:%M:%S')} - {entry}\n")

# === Display Output ===
def output(msg, gui=None):
    if gui:
        gui.display(msg)
    else:
        print(msg)

# === Message Receiver Thread ===
def receive_messages(sock, private_key, gui=None):
    global aes_key
    while True:
        try:
            data, _ = sock.recvfrom(4096)
            decoded = base64.b64decode(data)

            # Step 1: Handle ACKs
            if decoded.startswith(b"ACK:"):
                ack_id = int(decoded[4:].decode())
                if ack_id in pending_acks:
                    del pending_acks[ack_id]
                    log_event(f"ACK received for msg_id {ack_id}")
                continue

            # Step 2: Handle AES Key Exchange
            if aes_key is None:
                aes_key = decrypt_with_rsa(private_key, decoded)
                output("[System] AES key received and decrypted.", gui)
                log_event("AES key securely received")

                encrypted = encrypt_with_aes(aes_key, username)
                mac = create_hmac(aes_key, encrypted)
                sock.sendto(base64.b64encode(mac + encrypted), server_addr)
                continue

            # Step 3: Validate and parse incoming message
            if len(decoded) < 36:
                continue

            msg_id = int.from_bytes(decoded[:4], "big")
            if msg_id in received_ids:
                continue
            received_ids.add(msg_id)

            mac = decoded[4:36]
            encrypted_msg = decoded[36:]

            # Step 4: Verify and decrypt message
            if verify_hmac(aes_key, encrypted_msg, mac):
                message = decrypt_with_aes(aes_key, encrypted_msg)
                output(message, gui)
                sock.sendto(f"ACK:{msg_id}".encode(), server_addr)
                log_event(f"Received msg_id {msg_id}: {message}")
            else:
                output("[Warning] Message verification failed.", gui)
        except Exception:
            continue

# === Retransmit Unacknowledged Messages ===
def retransmit_thread(sock):
    while True:
        time.sleep(2)
        for msg_id in list(pending_acks.keys()):
            timestamp, msg = pending_acks[msg_id]
            if time.time() - timestamp > 2:
                sock.sendto(base64.b64encode(msg), server_addr)
                pending_acks[msg_id] = (time.time(), msg)
                log_event(f"Retransmitted msg_id {msg_id}")

# === Send Encrypted Message ===
def send_message(sock, text, gui=None):
    global msg_counter
    if aes_key:
        full_msg = f"{username}: {text}"
        encrypted = encrypt_with_aes(aes_key, full_msg)
        mac = create_hmac(aes_key, encrypted)
        msg_id_bytes = msg_counter.to_bytes(4, "big")
        msg = msg_id_bytes + mac + encrypted

        sock.sendto(base64.b64encode(msg), server_addr)
        pending_acks[msg_counter] = (time.time(), msg)
        log_event(f"Sent msg_id {msg_counter}: {full_msg}")
        msg_counter += 1

        if gui:
            gui.clear_entry()
    else:
        output("[System] Still waiting for AES key...", gui)

# === Tkinter GUI Class ===
class ChatGUI:
    def __init__(self, sock, private_key):
        self.sock = sock
        self.private_key = private_key
        self.root = tk.Tk()
        self.root.title("Secure UDP Chat")

        self.chat_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state='disabled', height=20, width=60)
        self.chat_area.pack(padx=10, pady=5)

        self.entry_field = tk.Entry(self.root, width=50)
        self.entry_field.pack(side=tk.LEFT, padx=10, pady=5)
        self.entry_field.bind("<Return>", lambda event: self.send())

        self.send_button = tk.Button(self.root, text="Send", command=self.send)
        self.send_button.pack(side=tk.RIGHT, padx=10)

        self.display("[System] Waiting for AES key...")

        threading.Thread(target=receive_messages, args=(self.sock, self.private_key, self), daemon=True).start()
        threading.Thread(target=retransmit_thread, args=(self.sock,), daemon=True).start()

        self.root.protocol("WM_DELETE_WINDOW", self.root.destroy)

    def display(self, message):
        self.chat_area.configure(state='normal')
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.configure(state='disabled')
        self.chat_area.see(tk.END)

    def send(self):
        text = self.entry_field.get().strip()
        if text:
            send_message(self.sock, text, self)

    def clear_entry(self):
        self.entry_field.delete(0, tk.END)

    def run(self):
        self.root.mainloop()

# === GUI Launch Function ===
def run_gui_mode():
    global aes_key, username
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    private_key, public_key = generate_rsa_keypair()
    sock.sendto(base64.b64encode(public_key), server_addr)

    root = tk.Tk()
    root.withdraw()
    username_input = simpledialog.askstring("Username", "Enter your name:", parent=root)
    if not username_input:
        messagebox.showerror("Error", "Username is required.")
        return
    username = username_input

    gui = ChatGUI(sock, private_key)
    gui.display(f"[System] Welcome, {username}")
    gui.run()

# === Terminal Mode (Fallback) ===
def run_terminal_mode():
    global aes_key, username
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    private_key, public_key = generate_rsa_keypair()
    print("[System] RSA key generated.")
    sock.sendto(base64.b64encode(public_key), server_addr)
    print("[System] Public key sent to server.")

    username_input = input("Enter your name: ")
    username = username_input
    print(f"[System] Welcome, {username}")
    print("[System] Waiting for AES key...")

    threading.Thread(target=receive_messages, args=(sock, private_key), daemon=True).start()
    threading.Thread(target=retransmit_thread, args=(sock,), daemon=True).start()

    while True:
        msg = input("→ ")
        send_message(sock, msg)

# === Entry Point ===
if __name__ == "__main__":
    if "--gui" in sys.argv:
        run_gui_mode()
    else:
        run_terminal_mode()
