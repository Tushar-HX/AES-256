import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from tkinter import filedialog, messagebox, Tk, Button, Label, Entry, Frame
from tkinter import ttk

CHUNK_SIZE = 1024 * 1024  # 1MB

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(password, file_path):
    if not password or not file_path:
        messagebox.showerror('Error', 'Password and file are required!')
        return
    if len(password) < 10:
        messagebox.showerror('Error', 'Password must be at least 10 characters long!')
        return
    try:
        salt = os.urandom(16)
        key = generate_key(password, salt)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        filesize = os.path.getsize(file_path)
        progress['maximum'] = filesize
        read_bytes = 0
        with open(file_path, 'rb') as f:
            data = b''
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                data += chunk
                read_bytes += len(chunk)
                progress['value'] = read_bytes
                root.update_idletasks()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        with open(file_path, 'wb') as f:
            f.write(salt + iv + encrypted)
        progress['value'] = 0
        messagebox.showinfo('Success', 'File encrypted successfully!')
    except Exception as e:
        progress['value'] = 0
        messagebox.showerror('Error', f'Encryption failed: {e}')

def decrypt_file(password, file_path):
    if not password or not file_path:
        messagebox.showerror('Error', 'Password and file are required!')
        return
    if len(password) < 10:
        messagebox.showerror('Error', 'Password must be at least 10 characters long!')
        return
    try:
        filesize = os.path.getsize(file_path)
        progress['maximum'] = filesize
        read_bytes = 0
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            encrypted = b''
            read_bytes += 32
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                encrypted += chunk
                read_bytes += len(chunk)
                progress['value'] = min(read_bytes, filesize)
                root.update_idletasks()
        key = generate_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        with open(file_path, 'wb') as f:
            f.write(decrypted)
        progress['value'] = 0
        messagebox.showinfo('Success', 'File decrypted successfully!')
    except Exception as e:
        progress['value'] = 0
        messagebox.showerror('Error', f'Decryption failed: {e}')

def select_file(entry_widget):
    file_path = filedialog.askopenfilename()
    entry_widget.delete(0, 'end')
    entry_widget.insert(0, file_path)

root = Tk()
root.title('AES-256 File Encryption Tool')

progress = ttk.Progressbar(root, orient='horizontal', length=400, mode='determinate')
progress.pack(pady=10)

# Encryption Frame
encrypt_frame = Frame(root, padx=20, pady=10)
encrypt_frame.pack(fill='both', expand=True)
Label(encrypt_frame, text='AES Encryption', font=('Arial', 14, 'bold')).pack()
Label(encrypt_frame, text='Password:').pack()
enc_password_entry = Entry(encrypt_frame, show='*')
enc_password_entry.pack(fill='x')
Label(encrypt_frame, text='File:').pack()
enc_file_entry = Entry(encrypt_frame, width=40)
enc_file_entry.pack(fill='x')
Button(encrypt_frame, text='Browse', command=lambda: select_file(enc_file_entry)).pack(pady=2)
Button(
    encrypt_frame,
    text='Encrypt File',
    command=lambda: encrypt_file(enc_password_entry.get(), enc_file_entry.get())
).pack(pady=5)

# Decryption Frame
decrypt_frame = Frame(root, padx=20, pady=10)
decrypt_frame.pack(fill='both', expand=True)
Label(decrypt_frame, text='AES Decryption', font=('Arial', 14, 'bold')).pack()
Label(decrypt_frame, text='Password:').pack()
dec_password_entry = Entry(decrypt_frame, show='*')
dec_password_entry.pack(fill='x')
Label(decrypt_frame, text='Encrypted File:').pack()
dec_file_entry = Entry(decrypt_frame, width=40)
dec_file_entry.pack(fill='x')
Button(decrypt_frame, text='Browse', command=lambda: select_file(dec_file_entry)).pack(pady=2)
Button(
    decrypt_frame,
    text='Decrypt File',
    command=lambda: decrypt_file(dec_password_entry.get(), dec_file_entry.get())
).pack(pady=5)

root.mainloop()