
# 🛡️ End-to-End Encrypted LAN Chat (with GUI)

> ⚠️ **Disclaimer**  
> This application is intended for educational and experimental use only. Do not use this project in production or for transmitting real confidential data without a full security audit. The developers are not responsible for misuse or data leaks.

## 📦 About the Project

This Python project allows you to send encrypted messages over a local network using **end-to-end RSA encryption**. Both the client and server include a simple but functional **Tkinter GUI**. During connection, the client and server perform a public key **handshake** and then exchange encrypted messages.

## 🚀 Features

- 🔐 Full RSA-based handshake between client and server
- 🖥️ GUI for both client and server (Tkinter)
- 📬 Encrypted message exchange
- 📋 Real-time status updates in **JSON format** with timestamps
- ⚙️ Dynamic input for IP, port, and message — no need to modify code

## 🧰 Requirements

- Python 3.8 or higher
- [`cryptography`](https://pypi.org/project/cryptography/)
  ```bash
  pip install cryptography


## 📂 Files

* `client.py` – GUI client with encryption and status log
* `server.py` – GUI server with key exchange and logging
* (optional) `README.md`

## ▶️ How to Use

1. Generate the keys with ‘key generator (server or client).py’

2. Run the server (`server.py`)

   * Choose a port (e.g., 5050) and click “Start Server”
3. Then run the client (`client.py`)

   * Enter the server’s IP and port, type a message, and click “Send Message”
4. Watch the encrypted handshake and message flow live in the status log

## 📌 To-Do / Ideas

* Add AES encryption after RSA handshake
* Support multiple clients simultaneously
* Save logs to a file
