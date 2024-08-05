# from fastapi import FastAPI, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from typing import Dict, List
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import serialization, hashes
# import base64

# app = FastAPI()

# # Configure CORS
# origins = [
#     "http://localhost:5173",  # Frontend URL
# ]

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # Load RSA keys
# try:
#     with open("private_key.pem", "rb") as key_file:
#         private_key = serialization.load_pem_private_key(
#             key_file.read(),
#             password=None,
#         )

#     with open("public_key.pem", "rb") as key_file:
#         public_key = serialization.load_pem_public_key(
#             key_file.read(),
#         )
# except Exception as e:
#     raise RuntimeError(f"Error loading RSA keys: {str(e)}")

# class InputModel(BaseModel):
#     data: Dict[str, str]

# class DecryptModel(BaseModel):
#     data: Dict[str, str]

# class DecryptObjectsModel(BaseModel):
#     objects: List[Dict[str, str]]

# class EncryptObjectsModel(BaseModel):
#     objects: List[Dict[str, str]]

# def encrypt_with_rsa(public_key, plaintext: str) -> str:
#     try:
#         encrypted = public_key.encrypt(
#             plaintext.encode(),
#             padding.OAEP(
#                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                 algorithm=hashes.SHA256(),
#                 label=None
#             )
#         )
#         return base64.b64encode(encrypted).decode()
#     except Exception as e:
#         raise RuntimeError(f"Error encrypting with RSA: {str(e)}")

# def decrypt_with_rsa(private_key, ciphertext: str) -> str:
#     try:
#         decrypted = private_key.decrypt(
#             base64.b64decode(ciphertext),
#             padding.OAEP(
#                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                 algorithm=hashes.SHA256(),
#                 label=None
#             )
#         )
#         return decrypted.decode()
#     except Exception as e:
#         raise RuntimeError(f"Error decrypting with RSA: {str(e)}")

# @app.post("/encrypt")
# async def encrypt_data(input_model: InputModel):
#     try:
#         encrypted_data = {}
#         for key, value in input_model.data.items():
#             rsa_encrypted = encrypt_with_rsa(public_key, value)
#             encrypted_data[key] = rsa_encrypted
        
#         return {"data": encrypted_data}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Encryption error: {str(e)}")

# @app.post("/decrypt")
# async def decrypt_data(decrypt_model: DecryptModel):
#     try:
#         decrypted_data = {}
#         for key, value in decrypt_model.data.items():
#             rsa_decrypted = decrypt_with_rsa(private_key, value)
#             decrypted_data[key] = rsa_decrypted
        
#         return {"data": decrypted_data}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")

# @app.post("/decrypt_objects")
# async def decrypt_objects(decrypt_objects_model: DecryptObjectsModel):
#     try:
#         decrypted_objects = []
#         for obj in decrypt_objects_model.objects:
#             decrypted_obj = {}
#             for key, value in obj.items():
#                 decrypted_obj[key] = decrypt_with_rsa(private_key, value)
#             decrypted_objects.append(decrypted_obj)
        
#         return {"data": decrypted_objects}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")

# @app.post("/encrypt_objects")
# async def encrypt_objects(encrypt_objects_model: EncryptObjectsModel):
#     try:
#         encrypted_objects = []
#         for obj in encrypt_objects_model.objects:
#             encrypted_obj = {}
#             for key, value in obj.items():
#                 encrypted_obj[key] = encrypt_with_rsa(public_key, value)
#             encrypted_objects.append(encrypted_obj)
        
#         return {"data": encrypted_objects}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Encryption error: {str(e)}")


# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)


from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = FastAPI()

# Configure CORS
origins = [
    "http://localhost:5173",  # Frontend URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the public key to use for encryption
with open("public_key.pem", "rb") as key_file:
    correct_public_key = serialization.load_pem_public_key(key_file.read())

# Models
class PrivateKeyModel(BaseModel):
    private_key: str

class InputModel(BaseModel):
    data: Dict[str, str]

class DecryptModel(BaseModel):
    data: Dict[str, str]

class DecryptObjectsModel(BaseModel):
    objects: List[Dict[str, str]]

class EncryptObjectsModel(BaseModel):
    objects: List[Dict[str, str]]

# Utility functions for encryption/decryption
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

# Global variable to hold the validated private key
private_key_store = {}

@app.post("/verify_key")
async def verify_key(private_key_model: PrivateKeyModel):
    try:
        private_key = serialization.load_pem_private_key(
            private_key_model.private_key.encode(),
            password=None,
        )
        # Store the valid private key
        private_key_store["key"] = private_key
        return {"message": "Private key is valid"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid private key")

@app.post("/encrypt")
async def encrypt_data(input_model: InputModel):
    try:
        public_key = correct_public_key
        encrypted_data = {}
        for key, value in input_model.data.items():
            rsa_encrypted = encrypt_with_rsa(public_key, value)
            encrypted_data[key] = rsa_encrypted
        return {"data": encrypted_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption error: {str(e)}")

@app.post("/decrypt")
async def decrypt_data(decrypt_model: DecryptModel):
    try:
        private_key = private_key_store.get("key")
        if not private_key:
            raise HTTPException(status_code=400, detail="Private key not verified")
        decrypted_data = {}
        for key, value in decrypt_model.data.items():
            rsa_decrypted = decrypt_with_rsa(private_key, value)
            decrypted_data[key] = rsa_decrypted
        return {"data": decrypted_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")

@app.post("/decrypt_objects")
async def decrypt_objects(decrypt_objects_model: DecryptObjectsModel):
    try:
        private_key = private_key_store.get("key")
        if not private_key:
            raise HTTPException(status_code=400, detail="Private key not verified")
        decrypted_objects = []
        for obj in decrypt_objects_model.objects:
            decrypted_obj = {}
            for key, value in obj.items():
                decrypted_obj[key] = decrypt_with_rsa(private_key, value)
            decrypted_objects.append(decrypted_obj)
        return {"data": decrypted_objects}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")

@app.post("/encrypt_objects")
async def encrypt_objects(encrypt_objects_model: EncryptObjectsModel):
    try:
        public_key = correct_public_key
        encrypted_objects = []
        for obj in encrypt_objects_model.objects:
            encrypted_obj = {}
            for key, value in obj.items():
                encrypted_obj[key] = encrypt_with_rsa(public_key, value)
            encrypted_objects.append(encrypted_obj)
        return {"data": encrypted_objects}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
