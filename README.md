# Secure UDP Chat Application – COMPE 560 Graduate Project

**Student Name:** Kashmira Nitin Chavan  
**Course:** COMPE 560 – Computer Data Networks  
**Semester:** Spring 2025 
**Instructor:** Dr. Yusuf Ozturk  
**Submission Type:** Graduate-Level Project


## Project Overview
This project implements a secure, real-time chat application using:
- **Hybrid Cryptography:** RSA + AES
- **Reliable UDP:** Custom ACK + Retransmission logic
- **Message Authentication:** HMAC-SHA256
- **GUI:** Built gui feature

# Cryptographic Design Summary 
This project uses hybrid cryptography: RSA is used to securely exchange a randomly generated AES key between the server and each client. All messages are then encrypted using AES-CBC, and each message includes a HMAC-SHA256 to ensure authenticity and integrity. Messages include a unique ID for reliable delivery and de-duplication, with retransmissions handled manually over UDP.

# Assumptions:
All clients are running on the same network or machine.
AES key exchange is trusted since it’s local.

# Limitations:
No encryption between clients directly (server decrypts all messages).
No persistent message storage.
Not designed for internet-scale deployment (no NAT traversal or TLS).

## 🗂️ Files Included

`client.py`- GUI-based client with all crypto 
+ reliability.
`server.py`- UDP broadcast server handling key exchange. `crypto_utils.py`- RSA/AES/HMAC helper functions                  
`README.md`- This documentation file             


▶️ How to Run the Project

### 1. Install Requirements 
pip install pycryptodome
# Run the Server
 python server.py  
# Run the client
 python client.py  
# Run the GUI
  python client.py --gui

📚 Documentation (Sphinx):
# Install Sphinx and the ReadTheDocs theme:
pip install sphinx sphinx_rtd_theme

# Generate HTML Docs
cd docs
python -m sphinx -b html source build/html
start build/html/index.html   # Windows

