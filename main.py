from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

app = FastAPI()

origins = [
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


with open("public_key.pem", "rb") as key_file:
    correct_public_key = serialization.load_pem_public_key(key_file.read())

class PrivateKeyModel(BaseModel):
    private_key: str

class InputModel(BaseModel):
    data: Dict[str, str]

class DecryptModel(BaseModel):
    data: Dict[str, Dict[str, str]]

def load_aes_key_iv(filename):
    """Carga la clave AES y el IV desde un archivo .pem"""
    with open(filename, "r") as pem_file:
        lines = pem_file.readlines()
        aes_key = lines[1].strip()
        iv = lines[4].strip()
    return bytes.fromhex(aes_key), bytes.fromhex(iv)

def encrypt_with_aes(aes_key, iv, plaintext: str) -> str:
    """Cifra el texto plano usando AES y IV."""
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode()

def decrypt_with_aes(aes_key, iv, ciphertext: str) -> str:
    """Descifra el texto cifrado usando AES y IV."""
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
    return plaintext.decode()

def encrypt_with_rsa(public_key, plaintext: str) -> str:
    encrypted = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_with_rsa(private_key, ciphertext: str) -> str:
    decrypted = private_key.decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def hybrid_encrypt(public_key, aes_key, iv, plaintext: str) -> Dict[str, str]:
    """Cifra los datos con AES y luego cifra la clave AES con RSA."""
    aes_encrypted_data = encrypt_with_aes(aes_key, iv, plaintext)
    rsa_encrypted_key = encrypt_with_rsa(public_key, aes_key.hex())
    return {
        "aes_encrypted_data": aes_encrypted_data,
        "rsa_encrypted_key": rsa_encrypted_key,
        "iv": base64.b64encode(iv).decode()
    }

def hybrid_decrypt(private_key, rsa_encrypted_key: str, iv: str, aes_encrypted_data: str) -> str:
    """Descifra la clave AES con RSA y luego descifra los datos con AES."""
    aes_key_hex = decrypt_with_rsa(private_key, rsa_encrypted_key)
    aes_key = bytes.fromhex(aes_key_hex)
    iv_bytes = base64.b64decode(iv)
    return decrypt_with_aes(aes_key, iv_bytes, aes_encrypted_data)

# Variable global para almacenar la clave privada verificada
private_key_store = {}

@app.post("/verify_key")
async def verify_key(private_key_model: PrivateKeyModel):
    try:
        private_key = serialization.load_pem_private_key(
            private_key_model.private_key.encode(),
            password=None,
        )
        private_key_store["key"] = private_key
        return {"message": "Private key is valid"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Llave incorrecta")

@app.post("/encrypt")
async def encrypt_data(input_model: InputModel):
    try:
        public_key = correct_public_key
        aes_key, iv = load_aes_key_iv("aes_key.pem")
        encrypted_data = {}
        for key, value in input_model.data.items():
            hybrid_encrypted = hybrid_encrypt(public_key, aes_key, iv, value)
            encrypted_data[key] = hybrid_encrypted
        return {"data": encrypted_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption error: {str(e)}")

@app.post("/decrypt")
async def decrypt_data(decrypt_model: DecryptModel):
    try:
        if "key" not in private_key_store:
            raise HTTPException(status_code=400, detail="Private key not verified")

        private_key = private_key_store["key"]

        decrypted_data = {}
        for key, encrypted_info in decrypt_model.data.items():
            rsa_encrypted_key = encrypted_info["rsa_encrypted_key"]
            aes_encrypted_data = encrypted_info["aes_encrypted_data"]
            iv = encrypted_info["iv"]

            # Descifrar datos híbridos
            plaintext = hybrid_decrypt(private_key, rsa_encrypted_key, iv, aes_encrypted_data)
            decrypted_data[key] = plaintext

        return {"data": decrypted_data}

    except Exception as e:
        error_message = str(e) if not isinstance(e, str) else e
        raise HTTPException(status_code=500, detail=f"Decryption error: {error_message}")

@app.post("/encrypt_objects")
async def encrypt_objects(input_objects: List[Dict[str, str]]):
    try:
        # Verificar que la lista no esté vacía
        if not input_objects:
            raise HTTPException(status_code=400, detail="Input objects list is empty")

        public_key = correct_public_key
        aes_key, iv = load_aes_key_iv("aes_key.pem")
        encrypted_objects = []

        for obj in input_objects:
            encrypted_data = {}
            for key, value in obj.items():
                if not value:  # Verifica que el valor no esté vacío
                    raise HTTPException(status_code=400, detail=f"Value for key '{key}' is empty")
                
                try:
                    hybrid_encrypted = hybrid_encrypt(public_key, aes_key, iv, value)
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Failed to encrypt value for key '{key}'")
                
                encrypted_data[key] = hybrid_encrypted
            encrypted_objects.append(encrypted_data)

        return {"data": encrypted_objects}

    except HTTPException as e:
        # Re-lanzar excepciones HTTP conocidas
        raise e
    except Exception as e:
        # Captura cualquier otro tipo de excepción
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/decrypt_objects")
async def decrypt_objects(input_objects: List[Dict[str, Dict[str, str]]]):
    try:
        if "key" not in private_key_store:
            raise HTTPException(status_code=400, detail="Private key not verified")

        private_key = private_key_store["key"]
        decrypted_objects = []

        for encrypted_obj in input_objects:
            decrypted_data = {}
            for key, encrypted_info in encrypted_obj.items():
                rsa_encrypted_key = encrypted_info["rsa_encrypted_key"]
                aes_encrypted_data = encrypted_info["aes_encrypted_data"]
                iv = encrypted_info["iv"]

                plaintext = hybrid_decrypt(private_key, rsa_encrypted_key, iv, aes_encrypted_data)
                decrypted_data[key] = plaintext

            decrypted_objects.append(decrypted_data)
        return {"data": decrypted_objects}

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)