# 🔐 Syntecxhub_Encrypted_ChatApp
Build a client/server chat simulation where messages are encrypted using AES before sending. Implement socket communication (TCP) and symmetric encryption on messages. Include key-exchange or pre-shared key handling, and safe IV usage. Support multiple clients (basic concurrency) and message logging.

---

## ✨ Features

- 🔒 **Cipher**  : AES-256-GCM
- 🧂 **IV**      : 96-bit, 12 completely random bytes
- 🎲 **KeyExch** : ECDH P-256
- 📦 **KDF**     : HKDF-SHA256
- ⚠️ **Support** : multiple clients (basic concurrency) and message logging.

---
# 🚀 SyntecxHub Terminal Based ChatApp
<div align="center">
  <img src="assets/demo.gif" alt="SUCCESS Demo" width="900">
  <p align="center">
    <b>Figure: Demo </b>
  </p>
</div>

## 🛠️ Requirements

- Python 3.7+
- `cryptography>=42.0.0` library

Install dependencies:

```bash
pip install cryptography>=42.0.0
```

## 🚀 Usage

```bash
python server.py
```
