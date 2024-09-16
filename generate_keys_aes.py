from cryptography.hazmat.primitives.ciphers import algorithms
import os
from cryptography.hazmat.primitives import serialization

def generate_aes_key(key_size=256):
    """Genera una clave AES de un tamaño especificado (128, 192, 256 bits)."""
    if key_size not in [128, 192, 256]:
        raise ValueError("El tamaño de la clave debe ser de 128, 192, o 256 bits.")
    
    key = os.urandom(key_size // 8)  # Divide entre 8 para obtener el tamaño en bytes
    return key

def generate_iv():
    """Genera un vector de inicialización (IV) de tamaño adecuado para AES."""
    iv = os.urandom(algorithms.AES.block_size // 8)  # El tamaño del bloque es de 128 bits (16 bytes)
    return iv

def save_to_pem(filename, key, iv):
    """Guarda la clave AES y el IV en un archivo .pem."""
    with open(filename, 'wb') as pem_file:
        # Guardar la clave en formato PEM con una etiqueta
        pem_file.write(b"-----BEGIN AES KEY-----\n")
        pem_file.write(key.hex().encode('utf-8') + b"\n")
        pem_file.write(b"-----END AES KEY-----\n")
        
        # Guardar el IV en formato PEM con una etiqueta
        pem_file.write(b"-----BEGIN AES IV-----\n")
        pem_file.write(iv.hex().encode('utf-8') + b"\n")
        pem_file.write(b"-----END AES IV-----\n")

if __name__ == "__main__":
    aes_key = generate_aes_key()
    iv = generate_iv()

    # Guardar clave e IV en un archivo .pem
    save_to_pem('aes_key.pem', aes_key, iv)

    print("Clave AES y IV guardados en aes_key.pem")
