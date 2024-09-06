import mysql.connector
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import Tk, Label, Entry, Button, Text, END, messagebox, Frame, StringVar
import os

# Conexión a la base de datos MySQL
def connect_to_db():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root",  
            database="criptografia_db"
        )
        return connection
    except mysql.connector.Error as err:
        messagebox.showerror("Error", f"Error al conectar a la base de datos: {err}")
        return None

# Funciones para cifrado y descifrado
def encrypt_data(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    return ciphertext

def decrypt_data(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.decode('utf-8')

def handle_encrypt():
    plaintext = plaintext_entry.get("1.0", END).strip()
    key = key_entry.get().encode('utf-8')
    
    if len(key) != 16:
        messagebox.showerror("Error", "La clave debe tener 16 caracteres.")
        return
    
    ciphertext = encrypt_data(plaintext, key)
    ciphertext_hex = ciphertext.hex()

    # Guardar en la base de datos
    connection = connect_to_db()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute(
                "INSERT INTO datos_cifrados (texto_original, texto_cifrado, clave) VALUES (%s, %s, %s)",
                (plaintext, ciphertext_hex, key.decode('utf-8'))
            )
            connection.commit()
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Error al guardar en la base de datos: {err}")
        finally:
            cursor.close()
            connection.close()
    
    ciphertext_entry.delete("1.0", END)
    ciphertext_entry.insert(END, ciphertext_hex)

def handle_decrypt():
    ciphertext_hex = ciphertext_entry.get("1.0", END).strip()
    
    if len(ciphertext_hex) == 0:
        messagebox.showerror("Error", "El campo de texto cifrado está vacío.")
        return

    key = key_entry.get().encode('utf-8')
    
    if len(key) != 16:
        messagebox.showerror("Error", "La clave debe tener 16 caracteres.")
        return
    
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = decrypt_data(ciphertext, key)
        plaintext_entry.delete("1.0", END)
        plaintext_entry.insert(END, plaintext)
    except Exception as e:
        messagebox.showerror("Error", f"Falló el descifrado. Asegúrate de que la clave es correcta y el texto cifrado es válido. Error: {e}")

# Interfaz Gráfica con Tkinter mejorada
root = Tk()
root.title("Cifrado y Descifrado de Datos")

# Estilo de la ventana principal
root.configure(bg="#2c3e50")
root.geometry("600x400")

# Frame contenedor para un mejor diseño
frame = Frame(root, bg="#ecf0f1", padx=10, pady=10)
frame.place(relx=0.5, rely=0.5, anchor='center')

# Clave de Cifrado/Descifrado
key_var = StringVar()
Label(frame, text="Clave (16 caracteres):", bg="#ecf0f1", font=("Arial", 12)).grid(row=0, column=0, pady=5, sticky='e')

# Validar longitud de entrada (solo 16 caracteres permitidos)
def validate_key_length(char, value):
    if len(value) < 16:
        return True
    elif len(value) == 16 and char in ('', ' '):
        return False
    return False

validate_key_cmd = root.register(validate_key_length)
key_entry = Entry(frame, width=40, textvariable=key_var, show='*', validate='key', validatecommand=(validate_key_cmd, '%S', key_var))
key_entry.grid(row=0, column=1, pady=5, padx=10)

# Texto Plano (variable longitud)
Label(frame, text="Texto a Cifrar:", bg="#ecf0f1", font=("Arial", 12)).grid(row=1, column=0, pady=5, sticky='e')
plaintext_entry = Text(frame, height=5, width=40, font=("Arial", 12))
plaintext_entry.grid(row=1, column=1, pady=5, padx=10)

# Botón de Cifrado
encrypt_button = Button(frame, text="Cifrar", command=handle_encrypt, bg="#27ae60", fg="white", font=("Arial", 12))
encrypt_button.grid(row=2, column=0, pady=10)

# Botón de Descifrado
decrypt_button = Button(frame, text="Descifrar", command=handle_decrypt, bg="#2980b9", fg="white", font=("Arial", 12))
decrypt_button.grid(row=2, column=1, pady=10)

# Texto Cifrado
Label(frame, text="Texto Cifrado (hexadecimal):", bg="#ecf0f1", font=("Arial", 12)).grid(row=3, column=0, pady=5, sticky='e')
ciphertext_entry = Text(frame, height=5, width=40, font=("Arial", 12))
ciphertext_entry.grid(row=3, column=1, pady=5, padx=10)

# Iniciar el bucle principal de la interfaz
root.mainloop()

