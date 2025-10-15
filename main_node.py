import json
import paho.mqtt.client as mqtt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pubkeys import pubkey_dictionary as diccionario_claves



# ========== CONFIGURACIÓN ==========
def cargar_configuracion(ruta="config.json"):
    with open(ruta, "r", encoding="utf-8") as archivo:
        return json.load(archivo)

# ========== GESTIÓN DE CLAVES ==========


def obtener_clave_privada(ruta_archivo):
    with open(ruta_archivo, "rb") as archivo:
        return serialization.load_pem_private_key(
            archivo.read(),
            password=None,
            backend=default_backend()
        )

def obtener_clave_publica_externa(identificador):
    clave_base64 = diccionario_claves.get(identificador)
    if clave_base64 is None:
        return None
    datos_clave = ("ssh-rsa " + clave_base64).encode("ascii")
    return serialization.load_ssh_public_key(datos_clave, backend=default_backend())

# ========== UTILIDADES DE IDENTIFICADOR ==========
def codificar_identificador(texto):
    bytes_id = texto.encode("ascii")
    if len(bytes_id) > 5:
        return bytes_id[:5]
    return bytes_id.ljust(5, b"\x00")

def decodificar_identificador(bytes_id):
    texto = bytes_id[:5]
    texto = texto.strip(b"\x00")
    return texto.decode("ascii", errors="ignore")

# ========== OPERACIONES CRIPTOGRÁFICAS ==========
def cifrar_rsa(clave_publica, datos):
    return clave_publica.encrypt(
        datos,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def descifrar_rsa(clave_privada, datos):
    return clave_privada.decrypt(
        datos,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def cifrar_aes(clave, datos):
    cifrador = AESGCM(clave)
    vector_inicial = clave
    return cifrador.encrypt(vector_inicial, datos, None)

def descifrar_aes(clave, datos):
    cifrador = AESGCM(clave)
    vector_inicial = clave
    return cifrador.decrypt(vector_inicial, datos, None)

def cifrado_hibrido(clave_publica, contenido):
    clave_simetrica = AESGCM.generate_key(bit_length=128)
    contenido_cifrado = cifrar_aes(clave_simetrica, contenido)
    clave_cifrada = cifrar_rsa(clave_publica, clave_simetrica)
    return clave_cifrada + contenido_cifrado

def descifrado_hibrido(clave_privada, contenido_cifrado):
    tamano_clave = clave_privada.key_size // 8
    if len(contenido_cifrado) < tamano_clave:
        raise ValueError("Mensaje cifrado demasiado corto")
    
    clave_simetrica = descifrar_rsa(clave_privada, contenido_cifrado[:tamano_clave])
    contenido_original = descifrar_aes(clave_simetrica, contenido_cifrado[tamano_clave:])
    return contenido_original

# ========== CONSTRUCCIÓN Y PROCESAMIENTO DE MENSAJES ONION ==========
def crear_mensaje_onion(configuracion, remitente, mensaje, ruta):
    # Preparamos el mensaje final: (end, remitente, mensaje)
    mensaje_bytes = codificar_identificador("end") + codificar_identificador(remitente) + mensaje.encode("utf-8")
    
    # Ciframos para el último nodo
    clave_ultimo = obtener_clave_publica_externa(ruta[-1])
    if clave_ultimo is None:
        raise ValueError(f"No se encontró clave pública para {ruta[-1]}")
    mensaje_cifrado = cifrado_hibrido(clave_ultimo, mensaje_bytes)
    
    # Añadimos capas en orden inverso
    for i in range(len(ruta)-2, -1, -1):
        siguiente_salto = ruta[i+1]
        clave_actual = obtener_clave_publica_externa(ruta[i])
        if clave_actual is None:
            raise ValueError(f"No se encontró clave pública para {ruta[i]}")
        
        capa_interior = codificar_identificador(siguiente_salto) + mensaje_cifrado
        mensaje_cifrado = cifrado_hibrido(clave_actual, capa_interior)
    
    return mensaje_cifrado

def procesar_mensaje_onion(configuracion, mensaje_cifrado):
    try:
        clave_privada = obtener_clave_privada(configuracion["private_key_path"])
        mensaje_descifrado = descifrado_hibrido(clave_privada, mensaje_cifrado)
        
        siguiente_destino = decodificar_identificador(mensaje_descifrado[:5])
        if siguiente_destino.lower() != "end":
            contenido_interno = mensaje_descifrado[5:]
            return ("reenviar", siguiente_destino, contenido_interno)
        
        contenido_final = mensaje_descifrado[5:]
        emisor = decodificar_identificador(contenido_final[:5])
        texto_mensaje = contenido_final[5:].decode("utf-8", errors="ignore")
        return ("entregar", emisor, texto_mensaje)
        
    except Exception as error:
        return ("error", f"{type(error).__name__}: {error}")

# ========== CLIENTE MQTT ==========
def crear_cliente_mqtt(config):
    cliente = mqtt.Client()
    credenciales = config["broker"]
    cliente.username_pw_set(credenciales["user"], credenciales["password"])
    cliente.connect(credenciales["host"], credenciales["port"], credenciales["keepalive"])
    return cliente

def publicar_mensaje(topic, mensaje, config=None):
    if config is None:
        config = cargar_configuracion()
    cliente = crear_cliente_mqtt(config)
    cliente.publish(topic, mensaje)
    cliente.disconnect()

def suscribirse_topic(topic, manejador, config=None):
    if config is None:
        config = cargar_configuracion()
    cliente = crear_cliente_mqtt(config)
    cliente.subscribe(topic)
    cliente.on_message = manejador
    cliente.loop_forever()