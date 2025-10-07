# main.py
import os
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from pubkeys import pubkey_dictionary

# Constantes
AES_KEY_LEN = 16
USERID_LEN = 5
MQTT_BROKER = "18.101.140.151"
MQTT_USER = "sinf"
MQTT_PASSWORD = "sinf2025"


# Gestión de claves
def load_ssh_private_key(key_path: str = None, password: bytes = None):
    """Carga la clave privada SSH"""
    if key_path is None:
        key_path = os.path.expanduser("~/.ssh/id_rsa")

    try:
        with open(key_path, "rb") as key_file:
            key_data = key_file.read()
        
        # Intentar sin contraseña primero
        try:
            private_key = serialization.load_ssh_private_key(key_data, password=None)
            print("✅ Clave privada cargada (sin contraseña)")
            return private_key
        except:
            # Si falla, pedir contraseña
            if password is None:
                password = input("Introduce la contraseña de tu clave SSH: ").encode('utf-8')
            private_key = serialization.load_ssh_private_key(key_data, password=password)
            print("✅ Clave privada cargada (con contraseña)")
            return private_key
            
    except Exception as e:
        print(f"❌ Error cargando clave privada: {e}")
        return None

def load_public_key(user_id):
    """Carga la clave pública de otro nodo desde el diccionario"""
    base64_pubkey = pubkey_dictionary.get(user_id)
    if base64_pubkey is None:
        raise ValueError(f"No se encontró clave pública para: {user_id}")

    if base64_pubkey.startswith("AAAAC3NzaC1lZDI1NTE5"):
        key_type = "ssh-ed25519"
    elif base64_pubkey.startswith("AAAAE2VjZHNhLXNoYTItbmlzdHAy"):
        key_type = "ecdsa-sha2-nistp256"
    elif base64_pubkey.startswith("AAAAB3NzaC1yc2E"):
        key_type = "ssh-rsa"
    else:
        key_type = "ssh-rsa"

    ssh_format = f"{key_type} {base64_pubkey}"
    return serialization.load_ssh_public_key(ssh_format.encode('ascii'))

# Funciones auxiliares para manejo de user IDs
def userid_to_bytes(user_id: str) -> bytes:
    """Convierte user_id a exactamente USERID_LEN bytes con padding"""
    return user_id.encode('utf-8').ljust(USERID_LEN, b'\x00')

def userid_from_bytes(user_id_bytes: bytes) -> str:
    """Convierte bytes de user_id de vuelta a string"""
    return user_id_bytes.rstrip(b'\x00').decode('utf-8')

def pack_message(sender_id: str, message: bytes) -> bytes:
    """Empaqueta mensaje en formato: [sender(5 bytes)][message(variable)]"""
    sender_bytes = userid_to_bytes(sender_id)
    return sender_bytes + message

def unpack_message(message_blob: bytes):
    """Desempaqueta mensaje: extrae sender y mensaje"""
    sender_bytes = message_blob[:USERID_LEN]
    message = message_blob[USERID_LEN:]
    return userid_from_bytes(sender_bytes), message

# =============================================================================
# ENCRIPTADO/DESENCRIPTADO HÍBRIDO COMPATIBLE
# =============================================================================

def hybrid_encrypt(public_key, plaintext: bytes) -> bytes:
    """
    Encriptado híbrido compatible con el sistema de tu amigo:
    - Usa la clave como nonce (primeros 12 bytes)
    - No envía nonce por separado
    """
    # Generar clave simétrica
    sym_key = os.urandom(AES_KEY_LEN)
    
    # Encriptar clave simétrica con RSA-OAEP
    encrypted_sym_key = public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Encriptar datos con AES-GCM usando la clave como nonce
    aesgcm = AESGCM(sym_key)
    nonce = sym_key[:12]  # Usar primeros 12 bytes de la clave como nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return encrypted_sym_key + ciphertext

def hybrid_decrypt(private_key, ciphertext_blob: bytes) -> bytes:
    """
    Desencriptado híbrido compatible con el sistema de tu amigo:
    - Extrae encrypted_sym_key y ciphertext
    - Usa la clave desencriptada como nonce
    """
    # Tamaño del bloque RSA
    rsa_size = private_key.key_size // 8
    
    # Extraer componentes
    encrypted_sym_key = ciphertext_blob[:rsa_size]
    aes_ciphertext = ciphertext_blob[rsa_size:]

    # Desencriptar clave simétrica
    sym_key = private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Desencriptar datos usando la clave como nonce
    aesgcm = AESGCM(sym_key)
    nonce = sym_key[:12]  # Usar primeros 12 bytes de la clave como nonce
    plaintext = aesgcm.decrypt(nonce, aes_ciphertext, None)
    return plaintext

# =============================================================================
# CONSTRUCCIÓN Y PROCESAMIENTO DE CEBOLAS
# =============================================================================

def build_onion(path: list[str], message: bytes, anonymous: bool) -> bytes:
    """
    Construye mensaje onion compatible
    """
    if len(path) < 2:
        raise ValueError("La ruta debe tener al menos 2 nodos")

    sender = path[0]

    # Mensaje interno (con o sin anonimato)
    if anonymous:
        inner_msg = pack_message("none", message)
    else:
        inner_msg = pack_message(sender, message)

    # Capa final
    current_payload = pack_message("end", inner_msg)

    # Encriptar para destinatario final
    receiver_pubkey = load_public_key(path[-1])
    current_payload = hybrid_encrypt(receiver_pubkey, current_payload)

    # Construir capas desde el final hacia el principio
    for i in range(len(path) - 2, -1, -1):
        current_hop = path[i]
        next_hop = path[i + 1]

        # Formato: [next_hop(5 bytes)][payload_anidado]
        next_hop_bytes = userid_to_bytes(next_hop)
        to_encrypt = next_hop_bytes + current_payload

        # Encriptar con clave pública del nodo actual
        current_pubkey = load_public_key(current_hop)
        current_payload = hybrid_encrypt(current_pubkey, to_encrypt)

    return current_payload

def process_onion_message(private_key, ciphertext: bytes):
    """
    Procesa una capa de cebolla con mejor manejo de errores
    """
    try:
        print(f"🔍 Procesando mensaje de {len(ciphertext)} bytes")
        
        plaintext = hybrid_decrypt(private_key, ciphertext)
        print(f"✅ Descifrado correcto, plaintext de {len(plaintext)} bytes")

        # Extraer next_hop y payload interno
        next_hop_bytes = plaintext[:USERID_LEN]
        inner_payload = plaintext[USERID_LEN:]

        next_hop = userid_from_bytes(next_hop_bytes)
        print(f"📨 Next hop: '{next_hop}', payload interno: {len(inner_payload)} bytes")
        
        return next_hop, inner_payload

    except Exception as e:
        print(f"❌ Error procesando mensaje onion: {e}")
        print(f"🔍 Tamaño ciphertext: {len(ciphertext)} bytes")
        print(f"🔍 Tamaño clave RSA: {private_key.key_size} bits")
        import traceback
        traceback.print_exc()
        raise

# =============================================================================
# CLASE TOR NODE
# =============================================================================

class TorNode:
    def __init__(self, user_id: str, key_path: str = None, password: bytes = None):
        self.user_id = user_id
        self.private_key = load_ssh_private_key(key_path, password)

        if self.private_key is None:
            raise ValueError(f"No se pudo cargar la clave privada para {user_id}")

        self.mqtt_client = None
        self.running = False

    def setup_mqtt(self):
        """Configura conexión MQTT"""
        self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)

        self.mqtt_client.on_connect = self._on_connect
        self.mqtt_client.on_message = self._on_message

        try:
            self.mqtt_client.connect(MQTT_BROKER, 1883, 60)
            print("✅ Conectado al broker MQTT")
            return True
        except Exception as e:
            print(f"❌ Error conectando a MQTT: {e}")
            return False

    def _on_connect(self, client, userdata, flags, rc, properties):
        if rc == 0:
            client.subscribe(self.user_id)
            print(f"📡 Suscrito al canal: {self.user_id}")
        else:
            print(f"❌ Error de conexión MQTT: {rc}")

    def _on_message(self, client, userdata, msg):
        try:
            print(f"\n📨 Mensaje recibido en {self.user_id} ({len(msg.payload)} bytes)")

            # Procesar capa de cebolla
            next_hop, payload = process_onion_message(self.private_key, msg.payload)

            if next_hop == "end":
                # Destino final - extraer mensaje
                sender, message = unpack_message(payload)
                print(f"🎯 MENSAJE FINAL de {sender}: {message.decode('utf-8')}")
            else:
                # Relay - reenviar al siguiente hop
                print(f"🔄 Reenviando a {next_hop}")
                self.send_direct_message(next_hop, payload)

        except Exception as e:
            print(f"❌ Error procesando mensaje: {e}")

    def start_listening(self):
        """Inicia escucha en segundo plano"""
        if self.mqtt_client:
            self.mqtt_client.loop_start()
            print("🎧 Iniciando escucha en segundo plano...")
        else:
            print("❌ Cliente MQTT no inicializado")

    def stop(self):
        """Detiene el nodo"""
        self.running = False
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        print(f"👋 Nodo {self.user_id} detenido")

    def send_direct_message(self, recipient: str, message: bytes):
        """Envía mensaje directo via MQTT"""
        if self.mqtt_client:
            self.mqtt_client.publish(recipient, message)
            print(f"📤 Mensaje enviado a {recipient}")
        else:
            print("❌ Cliente MQTT no inicializado")

    def send_onion_message(self, path: list[str], message: bytes, anonymous: bool = False):
        """Envía mensaje through onion routing"""
        if path[0] != self.user_id:
            raise ValueError("El primer elemento del path debe ser este nodo")

        onion = build_onion(path, message, anonymous)
        first_hop = path[1]

        print(f"🧅 Enviando onion a {first_hop} (ruta: {' -> '.join(path)})")
        self.send_direct_message(first_hop, onion)

# =============================================================================
# INTERFAZ DE USUARIO
# =============================================================================

def main():
    print("=== 🌐 NODO TOR - Sistema de Mensajería ===")

    # Configuración
    user_id = "bge"
    key_path = os.path.expanduser("~/.ssh/id_rsa")
    password = None  # Se pedirá interactivamente si es necesario

    print(f"🔑 User ID: {user_id}")
    print(f"📁 Clave: {key_path}")

    # Crear nodo
    try:
        node = TorNode(user_id, key_path, password)
        print("✅ Nodo creado correctamente")
    except Exception as e:
        print(f"❌ Error creando nodo: {e}")
        return

    # Configurar MQTT
    if not node.setup_mqtt():
        print("❌ No se pudo configurar MQTT")
        return

    # Iniciar escucha
    node.start_listening()

    # Menú principal
    while True:
        print(f"\n{'='*50}")
        print("🔐 SISTEMA ONION ROUTING - bge")
        print(f"{'='*50}")
        print("1. 📤 Enviar mensaje directo")
        print("2. 🔄 Enviar mensaje con múltiples hops")
        print("3. 🎭 Enviar mensaje anónimo")
        print("4. 👥 Ver usuarios disponibles")
        print("5. 🚪 Salir")
        print(f"{'='*50}")

        opcion = input("Selecciona una opción: ").strip()

        if opcion == "1":
            send_direct_message(node, user_id)
        elif opcion == "2":
            send_multi_hop_message(node, user_id)
        elif opcion == "3":
            send_anonymous_message(node, user_id)
        elif opcion == "4":
            show_network_status()
        elif opcion == "5":
            print("\n👋 Cerrando nodo...")
            node.stop()
            break
        else:
            print("❌ Opción no válida")

def send_direct_message(node, sender_id):
    """Envía mensaje directo a un destinatario"""
    print("\n--- Mensaje Directo ---")
    recipient = input("Destinatario: ").strip()
    message = input("Mensaje: ").strip()

    if not recipient or not message:
        print("❌ Destinatario y mensaje son obligatorios")
        return

    path = [sender_id, recipient]

    try:
        node.send_onion_message(path, message.encode('utf-8'), anonymous=False)
        print("✅ Mensaje enviado!")
    except Exception as e:
        print(f"❌ Error enviando mensaje: {e}")

def send_anonymous_message(node, sender_id):
    """Envía mensaje anónimo"""
    print("\n--- Mensaje Anónimo ---")
    recipient = input("Destinatario: ").strip()
    message = input("Mensaje: ").strip()

    if not recipient or not message:
        print("❌ Destinatario y mensaje son obligatorios")
        return

    path = [sender_id, recipient]

    try:
        node.send_onion_message(path, message.encode('utf-8'), anonymous=True)
        print("✅ Mensaje anónimo enviado!")
    except Exception as e:
        print(f"❌ Error enviando mensaje: {e}")

def send_multi_hop_message(node, sender_id):
    """Envía mensaje con múltiples saltos"""
    print("\n--- Ruta Múltiple ---")
    print("Ejemplo: bge,moi,jan,cfd")
    route_input = input("Ruta (separada por comas): ").strip()
    message = input("Mensaje: ").strip()

    if not route_input or not message:
        print("❌ Ruta y mensaje son obligatorios")
        return

    path = [node.strip() for node in route_input.split(',')]

    # Verificar que el primero sea el sender
    if path[0] != sender_id:
        path.insert(0, sender_id)

    if len(path) < 2:
        print("❌ La ruta debe tener al menos 2 nodos")
        return

    anonymous = input("¿Enviar anónimamente? (s/n): ").strip().lower() == 's'

    try:
        node.send_onion_message(path, message.encode('utf-8'), anonymous=anonymous)
        print(f"✅ Mensaje enviado por ruta: {' -> '.join(path)}")
    except Exception as e:
        print(f"❌ Error enviando mensaje: {e}")

def show_network_status():
    """Muestra estado de la red"""
    print("\n--- 🌐 Estado de la Red ---")
    print("📋 Nodos disponibles:")

    available_nodes = list(pubkey_dictionary.keys())
    for i in range(0, len(available_nodes), 4):
        line_nodes = available_nodes[i:i + 4]
        print("   " + "   ".join(f"{node:8}" for node in line_nodes))

    print(f"\n📊 Total de nodos: {len(available_nodes)}")

if __name__ == '__main__':
    main()
