🔐 Sistema de Enrutamiento Onion con MQTT
📋 Descripción
Implementación de un sistema de comunicación segura mediante enrutamiento onion y cifrado híbrido (RSA + AES-GCM), desarrollado para la asignatura de Seguridad de la Información.

✨ Características
Cifrado Híbrido: Combina RSA para el intercambio de claves y AES-GCM para el cifrado simétrico

Enrutamiento Onion: Mensajes cifrados en múltiples capas para preservar el anonimato

Comunicación MQTT: Usa broker MQTT como intermediario para la transmisión de mensajes

Anonimato Opcional: Permite enviar mensajes de forma anónima o identificada

🏗️ Estructura del Proyecto
text
practica_final/
├── main_node.py              # Módulo principal con toda la lógica
├── nodo_receptor.py          # Nodo para recibir mensajes
├── nodo_emisor.py           # Nodo para enviar mensajes
├── config.json              # Configuración del nodo
├── id_rsa                   # Clave privada (NO SUBIR A GIT)
├── id_rsa.pub              # Clave pública
├── pubkeys                 #diccionario de claves públicas
└── README.md               # Este archivo
⚙️ Instalación y Configuración
Prerrequisitos
bash
pip install paho-mqtt cryptography colorama
Configuración
Claves RSA: Genera un par de claves si no las tienes:

bash
ssh-keygen -m PEM -t rsa -b 2048 -f id_rsa
Configuración del nodo: Edita config.json:

json
{
  "uid": "bge",
  "private_key_path": "id_rsa",
  "public_key_path": "id_rsa.pub",
  "broker": {
    "host": "",
    "port": ,
    "user": "",
    "pass": "",
    "keepalive": 60
  },
  "send": {
    "anonymous": false,
    "message": "Mensaje de prueba",
    "path": ["bge", "bge"]
  }
}
Claves públicas: Añade las claves de otros nodos en main_node.py:

python
diccionario_claves = {
    "bge": "tu_clave_publica_en_base64",
    "svf": "clave_publica_svf",
    "ancr": "clave_publica_ancr"
}
🚀 Uso
Ejecutar Nodo Receptor
bash
python nodo_receptor.py
El nodo comenzará a escuchar mensajes en el canal MQTT correspondiente a tu ID.

Enviar Mensaje
bash
python nodo_emisor.py
Esto enviará el mensaje configurado a través de la ruta especificada.

Configurar Envío
Modifica la sección "send" en config.json:

"anonymous": true para mensajes anónimos, false para identificados

"message": El texto del mensaje a enviar

"path": Array con la ruta de nodos: ["origen", "salto1", "salto2", "destino"]
