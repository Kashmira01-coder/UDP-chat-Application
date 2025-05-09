from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256




def log_event(entry):
    """Log a chat event to file."""
    ...

# Generates a 2048-bit RSA key pair.
# Returns (private_key_bytes, public_key_bytes)
def generate_rsa_keypair():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

# Encrypts data using a recipient's RSA public key.
def encrypt_with_rsa(public_key_bytes, message_bytes):
    pub_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message_bytes)

# Decrypts data using the RSA private key.
def decrypt_with_rsa(private_key_bytes, encrypted_bytes):
    priv_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(encrypted_bytes)

# Generates a random 128-bit AES key (16 bytes).
def generate_aes_key():
    return get_random_bytes(16)

# Encrypts plaintext using AES in CBC mode.
# Returns IV + ciphertext (both as bytes).
def encrypt_with_aes(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext

# Decrypts AES-CBC encrypted data using provided key and IV.
def decrypt_with_aes(key, encrypted):
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# Creates an HMAC (SHA256) for a message using a given key.
def create_hmac(key, message_bytes):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message_bytes)
    return h.digest()

# Verifies the received HMAC with a freshly computed one.
# Returns True if valid, False otherwise.
def verify_hmac(key, message_bytes, received_mac):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message_bytes)
    try:
        h.verify(received_mac)
        return True
    except ValueError:
        return False
