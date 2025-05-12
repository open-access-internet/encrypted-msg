import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime
import json

class ClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("E2EE Client")
        master.geometry("500x400")

        tk.Label(master, text="IP-adres:").pack()
        self.ip_entry = tk.Entry(master)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.pack()

        tk.Label(master, text="Poort:").pack()
        self.port_entry = tk.Entry(master)
        self.port_entry.insert(0, "5050")
        self.port_entry.pack()

        tk.Label(master, text="Bericht:").pack()
        self.message_entry = tk.Entry(master, width=50)
        self.message_entry.pack()

        self.start_button = tk.Button(master, text="Verstuur bericht", command=self.start_client_thread)
        self.start_button.pack(pady=10)

        self.status_box = scrolledtext.ScrolledText(master, height=10)
        self.status_box.pack(fill="both", expand=True)

    def log(self, message):
        timestamp = datetime.now().isoformat(timespec='seconds')
        log_entry = {"timestamp": timestamp, "message": message}
        self.status_box.insert(tk.END, json.dumps(log_entry) + "\n")
        self.status_box.see(tk.END)

    def start_client_thread(self):
        thread = threading.Thread(target=self.run_client)
        thread.start()

    def run_client(self):
        try:
            host = self.ip_entry.get()
            port = int(self.port_entry.get())
            message = self.message_entry.get()

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            self.log("Verbinding maken...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            self.log("Verbonden met server.")

            server_public_pem = s.recv(2048)
            server_public_key = serialization.load_pem_public_key(server_public_pem)
            self.log("Server public key ontvangen.")

            s.sendall(public_pem)
            self.log("Client public key verzonden.")

            encrypted = server_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            s.sendall(encrypted)
            self.log("Bericht versleuteld en verzonden.")

            encrypted_response = s.recv(4096)
            decrypted_response = private_key.decrypt(
                encrypted_response,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            self.log("Antwoord van server: " + decrypted_response)
            s.close()

        except Exception as e:
            messagebox.showerror("Fout", str(e))
            self.log("Fout: " + str(e))

if __name__ == "__main__":
    root = tk.Tk()
    gui = ClientGUI(root)
    root.mainloop()
