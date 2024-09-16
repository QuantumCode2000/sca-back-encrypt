from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generar clave privada
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serializar clave privada a formato PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Guardar clave privada en un archivo
with open("private_key.pem", "wb") as f:
    f.write(private_pem)

# Obtener clave pública de la clave privada
public_key = private_key.public_key()

# Serializar clave pública a formato PEM
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Guardar clave pública en un archivo
with open("public_key.pem", "wb") as f:
    f.write(public_pem)

print("Claves generadas y guardadas en 'private_key.pem' y 'public_key.pem'")