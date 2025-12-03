server.py

#!/usr/bin/env python3
# server.py
import socket
import threading
import json
import base64
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from datetime import datetime

HOST = '0.0.0.0'
PORT = 9009
LOG_FILE = 'chat_log.txt'

# Diffie-Hellman params (small for demo; use larger primes in real apps)
DH_P = 0xFFFFFFFBFFFFFFFFFFFFFFFFFFFFFFFF  # example large-ish prime (not production grade)
DH_G = 5

clients_lock = threading.Lock()
clients = {}  
def log_message(sender, message):
    ts = datetime.utcnow().isoformat()
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{ts}\t{sender}\t{message}\n")

def hkdf_derive(shared_int: int) -> bytes:
    # derive 32-byte symmetric key from integer shared secret
    shared_bytes = shared_int.to_bytes((shared_int.bit_length()+7)//8, 'big')
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'chat-enc-key',
    )
    return hkdf.derive(shared_bytes)

def send_json(conn, obj):
    data = (json.dumps(obj) + '\n').encode()
    conn.sendall(data)

def recv_json(conn):
    # read until newline
    buffer = b''
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buffer += chunk
        if b'\n' in buffer:
            line, rest = buffer.split(b'\n', 1)
            # keep rest in socket? we won't handle extra as we always read full messages
            return json.loads(line.decode())

def handle_client(conn, addr):
    try:
        # 1) Perform basic DH key exchange
        # Receive client's initial message containing client_pub and optional name
        init = recv_json(conn)
        if init is None or init.get('type') != 'dh_init':
            conn.close()
            return
        client_pub = int(init['pub'])
        client_name = init.get('name', f"{addr[0]}:{addr[1]}")

        # Server generates private and public
        server_priv = int.from_bytes(os.urandom(32), 'big')
        server_pub = pow(DH_G, server_priv, DH_P)

        # Send server public
        send_json(conn, {'type': 'dh_reply', 'pub': str(server_pub)})

        # Derive shared secret
        shared = pow(client_pub, server_priv, DH_P)
        key = hkdf_derive(shared)  # 32 bytes AES key

        with clients_lock:
            clients[conn] = {'addr': addr, 'key': key, 'name': client_name}

        print(f"[+] {client_name} connected from {addr}")

        # Inform other clients about join (optional)
        broadcast_system_message(f"**{client_name} joined the chat**", sender="Server")

        # Main loop: receive encrypted messages
        while True:
            msg_json = recv_json(conn)
            if msg_json is None:
                break
            typ = msg_json.get('type')
            if typ == 'msg':
                b64 = msg_json.get('data')
                if not b64:
                    continue
                payload = base64.b64decode(b64)
                # AESGCM: nonce (12) + ciphertext
                nonce = payload[:12]
                ciphertext = payload[12:]
                aesgcm = AESGCM(key)
                try:
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
                except Exception as e:
                    print("Decryption failed:", e)
                    continue

                print(f"[{clients[conn]['name']}] {plaintext}")
                log_message(clients[conn]['name'], plaintext)

                # Broadcast plaintext to other clients, encrypted with their keys
                broadcast_plaintext(plaintext, sender=clients[conn]['name'], exclude_conn=conn)
            elif typ == 'quit':
                break
    except Exception as e:
        print("Client handler exception:", e)
    finally:
        with clients_lock:
            info = clients.pop(conn, None)
        if info:
            print(f"[-] {info['name']} disconnected")
            broadcast_system_message(f"**{info['name']} left the chat**", sender="Server")
        conn.close()

def broadcast_plaintext(plaintext, sender="Anonymous", exclude_conn=None):
    msg_text = f"{sender}: {plaintext}"
    with clients_lock:
        for c, meta in list(clients.items()):
            if c is exclude_conn:
                continue
            try:
                # encrypt with recipient's key
                aesgcm = AESGCM(meta['key'])
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, msg_text.encode(), None)
                payload = nonce + ct
                b64 = base64.b64encode(payload).decode()
                send_json(c, {'type': 'msg', 'data': b64})
            except Exception as e:
                print("Broadcast failed to", meta['addr'], e)

def broadcast_system_message(text, sender="System"):
    # same as broadcast_plaintext but used for system notices
    broadcast_plaintext(text, sender=sender)

def accept_loop():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(100)
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

if __name__ == "__main__":
    accept_loop()

client.py

#!/usr/bin/env python3
# client.py
import socket
import json
import base64
import threading
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9009

DH_P = 0xFFFFFFFBFFFFFFFFFFFFFFFFFFFFFFFF
DH_G = 5

def hkdf_derive(shared_int: int) -> bytes:
    shared_bytes = shared_int.to_bytes((shared_int.bit_length()+7)//8, 'big')
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'chat-enc-key',
    )
    return hkdf.derive(shared_bytes)

def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + '\n').encode())

def recv_json(conn):
    buffer = b''
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buffer += chunk
        if b'\n' in buffer:
            line, rest = buffer.split(b'\n', 1)
            return json.loads(line.decode())

def receive_loop(conn, aes_key):
    try:
        while True:
            msg = recv_json(conn)
            if msg is None:
                print("[*] Disconnected from server")
                break
            typ = msg.get('type')
            if typ == 'msg':
                b64 = msg.get('data')
                payload = base64.b64decode(b64)
                nonce = payload[:12]
                ciphertext = payload[12:]
                aesgcm = AESGCM(aes_key)
                try:
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
                except Exception as e:
                    print("Failed to decrypt message:", e)
                    continue
                print(plaintext)
    except Exception as e:
        print("Receiver exception:", e)

def main():
    name = input("Enter your display name: ").strip() or "Anonymous"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))

        # DH init
        priv = int.from_bytes(os.urandom(32), 'big')
        pub = pow(DH_G, priv, DH_P)
        send_json(sock, {'type': 'dh_init', 'pub': str(pub), 'name': name})

        reply = recv_json(sock)
        if reply is None or reply.get('type') != 'dh_reply':
            print("DH failed")
            return
        server_pub = int(reply['pub'])
        shared = pow(server_pub, priv, DH_P)
        key = hkdf_derive(shared)

        # Start receiver thread
        t = threading.Thread(target=receive_loop, args=(sock, key), daemon=True)
        t.start()

        aesgcm = AESGCM(key)
        print("You can now type messages. Type /quit to exit.")
        try:
            while True:
                line = input()
                if line.strip() == '':
                    continue
                if line.strip().lower() == '/quit':
                    send_json(sock, {'type': 'quit'})
                    break
                # encrypt
                nonce = os.urandom(12)
                ciphertext = aesgcm.encrypt(nonce, line.encode(), None)  # returns ct+tag
                payload = nonce + ciphertext
                b64 = base64.b64encode(payload).decode()
                send_json(sock, {'type': 'msg', 'data': b64})
        except KeyboardInterrupt:
            send_json(sock, {'type': 'quit'})

if __name__ == "__main__":
    main()





