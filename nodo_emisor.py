from main_node import cargar_configuracion, crear_mensaje_onion, publicar_mensaje

configuracion = cargar_configuracion()
id_local = configuracion["uid"]

es_anonimo = configuracion["send"].get("anonymous", False)
remitente = "none" if es_anonimo else id_local
texto = configuracion["send"]["message"]
camino = configuracion["send"]["path"]

print(f"Ruta: {' → '.join(camino)}")
print(f"Remitente: {'anónimo' if remitente == 'none' else remitente}")
print(f"Contenido: {texto}")

mensaje_cifrado = crear_mensaje_onion(configuracion, remitente, texto, camino)
publicar_mensaje(camino[0], mensaje_cifrado, configuracion)
print("Mensaje onion enviado al primer nodo de la ruta")