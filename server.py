import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime
import json

class ServerGUI:
    def __init__(self, master):
        self.master = master
        master.title("E2EE Server")
        master.geometry("500x400")

        tk.Label(master, text="Poort:").pack()
        self.port_entry = tk.Entry(master)
        self.port_entry.insert(0, "5050")
        self.port_entry.pack()

        self.start_button = tk.Button(master, text="Start Server", command=self.start_server_thread)
        self.start_button.pack(pady=10)

        self.status_box = scrolledtext.ScrolledText(master, height=15)
        self.status_box.pack(fill="both", expand=True)

    def log(self, message):
        timestamp = datetime.now().isoformat(timespec='seconds')
        log_entry = {"timestamp": timestamp, "message": message}
        self.status_box.insert(tk.END, json.dumps(log_entry) + "\\n")
        self.status_box.see(tk.END)

    def start_server_thread(self):
        thread = threading.Thread(target=self.run_server)
        thread.start()

    def run_server(self):
        try:
            port = int(self.port_entry.get())

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            host = '0.0.0.0'
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen(1)
            self.log(f"Server gestart op poort {port}, wacht op verbinding...")

            conn, addr = server_socket.accept()
            self.log(f"Verbonden met: {addr}")

            conn.sendall(public_pem)
            self.log("Server public key verzonden.")

            client_public_pem = conn.recv(2048)
            client_public_key = serialization.load_pem_public_key(client_public_pem)
            self.log("Client public key ontvangen.")

            encrypted_message = conn.recv(4096)
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode('utf-8')
            self.log(f"Ontvangen bericht: {decrypted_message}")

            response = "Bericht ontvangen."
            encrypted_response = client_public_key.encrypt(
                response.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            conn.sendall(encrypted_response)
            self.log("Versleuteld antwoord verzonden.")

            conn.close()
            server_socket.close()
            self.log("Verbinding gesloten.")

        except Exception as e:
            messagebox.showerror("Fout", str(e))
            self.log("Fout: " + str(e))

if __name__ == "__main__":
    root = tk.Tk()
    gui = ServerGUI(root)
    root.mainloop()
