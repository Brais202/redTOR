from main_node import cargar_configuracion, procesar_mensaje_onion, suscribirse_topic, publicar_mensaje

config = cargar_configuracion()
mi_id = config["uid"]


def manejar_mensaje_recibido(cliente, datos_usuario, mensaje):
    resultado = procesar_mensaje_onion(config, mensaje.payload)
    
    if isinstance(resultado, tuple) and resultado[0] == "reenviar":
        siguiente_nodo, contenido = resultado[1], resultado[2]
        print(f"Retransmitiendo: {mi_id} → {siguiente_nodo}")
        publicar_mensaje(siguiente_nodo, contenido, config)
    
    elif isinstance(resultado, tuple) and resultado[0] == "entregar":
        origen, texto = resultado[1], resultado[2]
        nombre_remitente = "anónimo" if origen == "none" else origen
        print(f"De: {nombre_remitente}")
        print(f"Mensaje: {texto}")
        

    elif isinstance(resultado, tuple) and resultado[0] == "error":
        print( f"Procesamiento fallido: {resultado[1]}")

print(f"Nodo {mi_id} escuchando mensajes...")
suscribirse_topic(mi_id, manejar_mensaje_recibido, config)