import os
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from PIL import Image, ImageTk
from crypto_tool import AESCipher

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Data Encryption & Decryption Tool")
        self.geometry("740x650")
        self.resizable(False, False)

        self.tabview = ctk.CTkTabview(self, width=700, height=600)
        self.tabview.pack(padx=20, pady=20, fill="both", expand=True)

        self.tab_photo = self.tabview.add("Photo / File Locker")
        self.tab_msg = self.tabview.add("Secret Messages")

        self.selected_file = None
        self.current_preview_img = None

        self.setup_photo_tab()
        self.setup_message_tab()

    # -------------------------------------------------------------
    # TAB 1: Photo & File Locker
    # -------------------------------------------------------------
    def setup_photo_tab(self):
        tab = self.tab_photo

        title = ctk.CTkLabel(tab, text="Encrypt & Decrypt Images / Files", font=ctk.CTkFont(size=18, weight="bold"))
        title.pack(pady=10)

        file_frame = ctk.CTkFrame(tab)
        file_frame.pack(fill="x", padx=20, pady=10)

        self.file_path_label = ctk.CTkLabel(file_frame, text="No file selected", wraplength=420, text_color="gray")
        self.file_path_label.pack(side="left", padx=15, pady=10)

        browse_btn = ctk.CTkButton(file_frame, text="Browse File / Photo", command=self.browse_file)
        browse_btn.pack(side="right", padx=15, pady=10)

        btn_frame = ctk.CTkFrame(tab)
        btn_frame.pack(pady=10)

        self.enc_btn = ctk.CTkButton(btn_frame, text="🔒 Lock / Encrypt", fg_color="#C0392B", hover_color="#962D22", command=self.encrypt_selected_file)
        self.enc_btn.pack(side="left", padx=10, pady=10)

        self.dec_btn = ctk.CTkButton(btn_frame, text="🔓 Unlock / Decrypt", fg_color="#27AE60", hover_color="#1E8449", command=self.decrypt_selected_file)
        self.dec_btn.pack(side="left", padx=10, pady=10)

        self.preview_label = ctk.CTkLabel(tab, text="\nImage preview will appear here\n(Encrypted files cannot be previewed)", text_color="gray")
        self.preview_label.pack(pady=10)

        self.file_status = ctk.CTkLabel(tab, text="", font=ctk.CTkFont(size=13))
        self.file_status.pack(pady=5)

    def browse_file(self):
        f = filedialog.askopenfilename(
            title="Select Image or Document",
            filetypes=[("All Files", "*.*"), ("Images", "*.png;*.jpg;*.jpeg;*.webp")]
        )
        if f:
            self.selected_file = f
            self.file_path_label.configure(text=os.path.basename(f), text_color="white")
            self.file_status.configure(text="")
            self.load_preview(f)

    def load_preview(self, path):
        if path.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            try:
                pil_img = Image.open(path)
                pil_img.thumbnail((220, 220))
                self.current_preview_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=pil_img.size)
                self.preview_label.configure(image=self.current_preview_img, text="")
                return
            except Exception:
                pass
        self.current_preview_img = None
        self.preview_label.configure(image=None, text="🔒 [ Scrambled / Encrypted Binary Data ]")

    def encrypt_selected_file(self):
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file or photo first!")
            return

        key_file = "aes_secret.key"
        if not os.path.exists(key_file):
            key = AESCipher.generate_key()
            AESCipher.save_key(key, key_file)
        else:
            key = AESCipher.load_key(key_file)

        try:
            with open(self.selected_file, "rb") as f:
                data = f.read()

            encrypted = AESCipher.encrypt(data, key)
            out_path = self.selected_file + ".enc"

            with open(out_path, "wb") as f:
                f.write(encrypted)

            self.selected_file = out_path
            self.file_path_label.configure(text=os.path.basename(out_path), text_color="white")
            self.file_status.configure(text=f"Encrypted file:\n{os.path.basename(out_path)}", text_color="#E74C3C")
            self.load_preview(out_path)
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {out_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_selected_file(self):
        if not self.selected_file or not self.selected_file.endswith(".enc"):
            messagebox.showwarning("Warning", "Select an encrypted (.enc) file to unlock!")
            return

        key_file = "aes_secret.key"
        if not os.path.exists(key_file):
            messagebox.showerror("Key Missing", "aes_secret.key file not found!")
            return

        key = AESCipher.load_key(key_file)

        try:
            with open(self.selected_file, "rb") as f:
                data = f.read()

            decrypted = AESCipher.decrypt(data, key)
            
            # Determine output name
            base_original = self.selected_file[:-4]  # Strip .enc
            if os.path.exists(base_original):
                name, ext = os.path.splitext(base_original)
                out_path = f"{name}_restored{ext}"
            else:
                out_path = base_original

            with open(out_path, "wb") as f:
                f.write(decrypted)

            self.selected_file = out_path
            self.file_path_label.configure(text=os.path.basename(out_path), text_color="white")
            self.file_status.configure(text=f"Restored file:\n{os.path.basename(out_path)}", text_color="#2ECC71")
            self.load_preview(out_path)
            messagebox.showinfo("Success", f"File restored successfully!\nSaved as: {out_path}")
        except Exception as e:
            messagebox.showerror("Decryption Failed", f"Invalid key or corrupted file: {e}")

    # -------------------------------------------------------------
    # TAB 2: Secret Text Messages
    # -------------------------------------------------------------
    def setup_message_tab(self):
        tab = self.tab_msg

        ctk.CTkLabel(tab, text="Secret Message Encryptor", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        self.msg_input = ctk.CTkTextbox(tab, width=640, height=110)
        self.msg_input.pack(pady=5)
        self.msg_input.insert("1.0", "Type secret message here...")

        btn_box = ctk.CTkFrame(tab)
        btn_box.pack(pady=10)

        ctk.CTkButton(btn_box, text="Encrypt Message", command=self.encrypt_text).pack(side="left", padx=10)
        ctk.CTkButton(btn_box, text="Decrypt Hex", fg_color="#27AE60", hover_color="#1E8449", command=self.decrypt_text).pack(side="left", padx=10)

        ctk.CTkLabel(tab, text="Result / Ciphertext:").pack(anchor="w", padx=30, pady=(5, 0))
        self.msg_output = ctk.CTkTextbox(tab, width=640, height=140)
        self.msg_output.pack(pady=5)

    def encrypt_text(self):
        raw_text = self.msg_input.get("1.0", "end-1c").encode("utf-8")
        if not raw_text:
            return
        key = AESCipher.generate_key()
        ct = AESCipher.encrypt(raw_text, key)

        output = f"CIPHERTEXT (Hex):\n{ct.hex()}\n\nSECRET KEY (Hex):\n{key.hex()}\n\n(Save this key to decrypt later!)"
        self.msg_output.delete("1.0", "end")
        self.msg_output.insert("1.0", output)

    def decrypt_text(self):
        dialog_ct = ctk.CTkInputDialog(text="Paste the Ciphertext Hex:", title="Decrypt Text")
        ct_hex = dialog_ct.get_input()
        if not ct_hex:
            return

        dialog_key = ctk.CTkInputDialog(text="Paste the Secret Key Hex:", title="Decrypt Text")
        key_hex = dialog_key.get_input()
        if not key_hex:
            return

        try:
            pt = AESCipher.decrypt(bytes.fromhex(ct_hex.strip()), bytes.fromhex(key_hex.strip()))
            self.msg_output.delete("1.0", "end")
            self.msg_output.insert("1.0", f"DECRYPTED MESSAGE:\n\n{pt.decode('utf-8')}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")


if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
