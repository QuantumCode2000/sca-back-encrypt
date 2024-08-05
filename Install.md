<!-- Install Project -->

# Install Project

## Pasos para instalar el proyecto

1. Clonar el repositorio

```git
git clone https://github.com/QuantumCode2000/sca-back-encrypt.git
```

2. Entrar a la carpeta del proyecto

```bash
cd sca-back-encrypt
```

3. Crear el entorno virtual

```bash
python3 -m venv venv
```

4. Activar el entorno virtual

```bash
source venv/bin/activate
```

5. Instalar las dependencias

```bash
pip install -r requirements.txt
```

6. Iniciar el servidor

```bash
fastapi dev main.py
```

## Posibles errores 

- Si al instalar las dependencias se presenta un error con el paquete `psycopg2` instalar el siguiente paquete

```bash
sudo apt-get install libpq-dev
```
- Si windows manda errores de Policy de ejecución de scripts, ejecutar el siguiente comando

```bash
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

