# 🔐 CyberSec Cryptography Toolkit & PIN Vault

An authenticated encryption suite featuring both a Python desktop GUI and a mobile-friendly client-side web application. It enables secure file locking, image encryption, confidential messaging, and algorithm performance benchmarking using symmetric (AES-256) and asymmetric (RSA-2048) cryptography.

---

## 🌐 Live Web Application
Test the live mobile/desktop web locker directly in your browser:
👉 **[Launch Live Vault](https://abishal-afk.github.io/crypto-tool/)**

---

## 🚀 Key Features

### 1. 4-Digit PIN Vault (Web Application)
* **Ephemeral PIN Mechanism**: Encrypt files or secret text messages and generate an auto-generated 4-digit PIN for simple peer-to-peer sharing.
* **Client-Side Zero-Knowledge**: Runs entirely in the client browser using the **W3C Web Cryptography API**. No data or keys are transmitted to any server.
* **Key Stretching**: Utilizes **PBKDF2** with **300,000 computation rounds** and a 16-byte cryptographically secure pseudo-random salt to resist brute-force attacks against short PINs.
* **Mobile-Responsive UI**: Dark-mode interface optimized for mobile browsers and instant messaging sharing (e.g., WhatsApp).

### 2. Desktop Application (Python GUI)
* **CustomTkinter Interface**: Dark-themed desktop dashboard with integrated visual preview for encrypted media.
* **Symmetric File Locker**: High-speed authenticated encryption and decryption of large documents, images, and arbitrary binary files.
* **Asymmetric Key Exchange**: RSA-2048 keypair generation, public key export (`.pem`), and private key protection for secure key transport.
* **Cryptographic Benchmarking**: Built-in benchmark suite measuring execution latency, throughput, and ciphertext expansion between AES and RSA.

---

## 🛡️ Technical Architecture

| Component | Standard / Algorithm | Specification |
| :--- | :--- | :--- |
| **Symmetric Cipher** | AES-GCM | 256-bit key, 96-bit random IV, 128-bit authentication tag |
| **Key Derivation** | PBKDF2-HMAC-SHA256 | 300,000 iterations + 16-byte random salt |
| **Asymmetric Cipher** | RSA-OAEP | 2048-bit modulus, $e = 65537$, SHA-256 hashing |
| **Integrity Assurance** | AEAD Tag Verification | Prevents tampering, bit-flipping, and padding oracle attacks |

---

## 💻 Desktop Installation & Setup

### Prerequisites
* Python 3.10+
* Git

### 1. Clone the Repository
```bash
git clone [https://github.com/Abishal-afk/crypto-tool.git](https://github.com/Abishal-afk/crypto-tool.git)
cd crypto-tool
