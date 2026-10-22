import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ---------------------------------------------------------
# 1. AES-256 Symmetric Cipher Engine
# ---------------------------------------------------------
class AESCipher:
    @staticmethod
    def generate_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def save_key(key: bytes, filename: str = "aes_secret.key"):
        with open(filename, "wb") as f:
            f.write(key)
        print(f"[+] AES Key saved to: {filename}")

    @staticmethod
    def load_key(filename: str = "aes_secret.key") -> bytes:
        with open(filename, "rb") as f:
            return f.read()

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------
# 2. RSA-2048 Asymmetric Cipher Engine
# ---------------------------------------------------------
class RSACipher:
    @staticmethod
    def generate_and_save_keys(priv_file="private_key.pem", pub_file="public_key.pem"):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Save Private Key
        with open(priv_file, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Save Public Key
        with open(pub_file, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        print(f"[+] RSA Keys saved to {priv_file} and {pub_file}")

    @staticmethod
    def load_private_key(filename: str = "private_key.pem"):
        with open(filename, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    @staticmethod
    def load_public_key(filename: str = "public_key.pem"):
        with open(filename, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    @staticmethod
    def encrypt(data: bytes, public_key) -> bytes:
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt(ciphertext: bytes, private_key) -> bytes:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


# ---------------------------------------------------------
# 3. File Encryption / Decryption Utilities
# ---------------------------------------------------------
def encrypt_file(filepath: str, key_path: str = "aes_secret.key"):
    if not os.path.exists(filepath):
        print(f"[-] Error: File '{filepath}' does not exist.")
        return

    if not os.path.exists(key_path):
        print(f"[*] No key found at '{key_path}'. Generating a new AES key...")
        key = AESCipher.generate_key()
        AESCipher.save_key(key, key_path)
    else:
        key = AESCipher.load_key(key_path)

    with open(filepath, "rb") as f:
        file_bytes = f.read()

    encrypted_data = AESCipher.encrypt(file_bytes, key)
    output_path = filepath + ".enc"

    with open(output_path, "wb") as f:
        f.write(encrypted_data)

    print(f"[+] File successfully encrypted: {output_path}")


def decrypt_file(filepath: str, key_path: str = "aes_secret.key"):
    if not os.path.exists(filepath):
        print(f"[-] Error: File '{filepath}' does not exist.")
        return

    if not os.path.exists(key_path):
        print(f"[-] Error: Key file '{key_path}' is missing.")
        return

    key = AESCipher.load_key(key_path)

    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted_data = AESCipher.decrypt(encrypted_data, key)
        output_path = filepath.replace(".enc", ".dec") if filepath.endswith(".enc") else filepath + ".dec"

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        print(f"[+] File successfully decrypted: {output_path}")
    except Exception as e:
        print(f"[-] Decryption failed! Invalid key or corrupted data. Details: {e}")


# ---------------------------------------------------------
# 4. Performance Benchmark
# ---------------------------------------------------------
def run_benchmark():
    sample_text = "Confidential Security Data Benchmark 2026"
    data = sample_text.encode("utf-8")
    print(f"\n[+] Testing with payload: '{sample_text}' ({len(data)} bytes)")
    print("=" * 60)

    # AES Test
    aes_key = AESCipher.generate_key()
    start = time.perf_counter()
    for _ in range(500):
        ct = AESCipher.encrypt(data, aes_key)
        _ = AESCipher.decrypt(ct, aes_key)
    aes_time = ((time.perf_counter() - start) / 500) * 1000

    print("--- AES-256 (GCM) ---")
    print(f"Output Ciphertext : {len(ct)} bytes")
    print(f"Avg Execution Time: {aes_time:.4f} ms")

    # RSA Test
    priv_k, pub_k = RSACipher.generate_keys() if hasattr(RSACipher, 'generate_keys') else (rsa.generate_private_key(65537, 2048), None)
    pub_k = priv_k.public_key()
    start = time.perf_counter()
    for _ in range(50):
        ct_rsa = RSACipher.encrypt(data, pub_k)
        _ = RSACipher.decrypt(ct_rsa, priv_k)
    rsa_time = ((time.perf_counter() - start) / 50) * 1000

    print("\n--- RSA-2048 (OAEP) ---")
    print(f"Output Ciphertext : {len(ct_rsa)} bytes")
    print(f"Avg Execution Time: {rsa_time:.4f} ms")

    print("=" * 60)
    print(f"[Result] AES is ~{rsa_time / max(aes_time, 0.0001):.1f}x faster than RSA.")


# ---------------------------------------------------------
# 5. Interactive CLI Menu
# ---------------------------------------------------------
def main():
    while True:
        print("\n" + "=" * 45)
        print("      DATA ENCRYPTION & DECRYPTION TOOL      ")
        print("=" * 45)
        print("1. Encrypt a Text Message (AES-256)")
        print("2. Decrypt a Text Message (AES-256)")
        print("3. Encrypt a File (Any format: PDF, TXT, PNG)")
        print("4. Decrypt a File (.enc)")
        print("5. Generate RSA Keypair (.pem files)")
        print("6. Run AES vs RSA Benchmark & Security Report")
        print("7. Exit")
        choice = input("\nSelect an option (1-7): ").strip()

        if choice == "1":
            msg = input("Enter text to encrypt: ").encode("utf-8")
            key = AESCipher.generate_key()
            ct = AESCipher.encrypt(msg, key)
            print(f"[+] Ciphertext (Hex): {ct.hex()}")
            print(f"[+] Secret Key (Hex): {key.hex()}")
            print("[*] Save both the key and ciphertext to decrypt later!")

        elif choice == "2":
            try:
                ct_hex = input("Enter ciphertext (Hex): ").strip()
                key_hex = input("Enter key (Hex): ").strip()
                pt = AESCipher.decrypt(bytes.fromhex(ct_hex), bytes.fromhex(key_hex))
                print(f"[+] Decrypted Message: {pt.decode('utf-8')}")
            except Exception as e:
                print(f"[-] Decryption failed: {e}")

        elif choice == "3":
            path = input("Enter full or relative path to file: ").strip().strip('"')
            encrypt_file(path)

        elif choice == "4":
            path = input("Enter path to .enc file: ").strip().strip('"')
            decrypt_file(path)

        elif choice == "5":
            RSACipher.generate_and_save_keys()

        elif choice == "6":
            run_benchmark()

        elif choice == "7":
            print("[*] Exiting program.")
            break
        else:
            print("[-] Invalid selection. Try again.")


if __name__ == "__main__":
    main()
