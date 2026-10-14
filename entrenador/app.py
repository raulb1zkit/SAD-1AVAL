#!/usr/bin/env python3
"""Servidor local del entrenador SAD. Persiste el progreso en data/progreso.json."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import random
from urllib.parse import urlparse

ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
STATE_FILE = DATA_DIR / "progreso.json"

QUESTIONS = [
    ("fundamentos", "Una debilidad que puede aprovechar una amenaza es:", ["Impacto", "Vulnerabilidad", "Activo", "Riesgo"], 1, "La vulnerabilidad es la debilidad; el ataque es la materialización de una amenaza."),
    ("fundamentos", "Escuchar tráfico sin modificarlo compromete sobre todo:", ["Disponibilidad", "Integridad", "Confidencialidad", "No repudio"], 2, "La interceptación es pasiva y busca obtener información."),
    ("fundamentos", "La secuencia correcta es:", ["Ataque → vulnerabilidad → amenaza", "Amenaza aprovecha vulnerabilidad → ataque → impacto", "Impacto → activo → ataque", "Riesgo → impacto → activo"], 1, "Una amenaza aprovecha una vulnerabilidad; al materializarse hay ataque e impacto."),
    ("raid", "¿Qué RAID no tolera el fallo de ningún disco?", ["RAID 0", "RAID 1", "RAID 5", "RAID 6"], 0, "RAID 0 solo reparte bloques; no tiene redundancia."),
    ("raid", "Con N discos, RAID 6 tiene una capacidad útil aproximada de:", ["N", "N - 1", "N - 2", "N / 2 siempre"], 2, "RAID 6 reserva el equivalente a dos discos para doble paridad."),
    ("raid", "Para una BBDD con mucha E/S y redundancia elegirías:", ["RAID 0", "RAID 5", "RAID 10", "JBOD"], 2, "RAID 10 combina espejos con striping y ofrece gran rendimiento."),
    ("cripto", "Una firma digital aporta por sí sola:", ["Confidencialidad", "Integridad, autenticidad y evidencia de autoría", "Disponibilidad", "Cifrado simétrico"], 1, "Firmar no cifra el contenido; protege integridad y vincula al firmante."),
    ("cripto", "Para enviar un dato confidencial a Ana se cifra con:", ["La clave privada de Ana", "La clave pública de Ana", "La clave pública del emisor", "El hash de Ana"], 1, "Ana descifra con su clave privada, por lo que se cifra para ella con su clave pública."),
    ("cripto", "El salt en contraseñas sirve principalmente para:", ["Cifrar el tráfico", "Evitar hashes iguales y rainbow tables", "Reemplazar MFA", "Firmar certificados"], 1, "Un salt único hace que la misma contraseña no produzca siempre el mismo hash."),
    ("cripto", "¿Cuál es MFA real?", ["Contraseña y PIN", "Dos contraseñas", "Contraseña y código de una app autenticadora", "Pregunta secreta y contraseña"], 2, "Contraseña = saber; código de una app/dispositivo = tener."),
    ("redes", "Falsear la asociación entre una IP y una MAC para interceptar tráfico es:", ["DNS spoofing", "ARP spoofing", "MAC flooding", "DHCP starvation"], 1, "ARP spoofing engaña a los equipos sobre qué MAC corresponde a una IP."),
    ("redes", "La defensa más directa frente a MAC flooding en un switch es:", ["DNSSEC", "Port Security", "DMARC", "CSP"], 1, "Port Security limita o fija las MAC admitidas por un puerto."),
    ("redes", "¿Qué combinación protege la autenticidad del correo de un dominio?", ["TLS, SSH y VPN", "SPF, DKIM y DMARC", "WEP, WPA y WPA2", "ARP y DNSSEC"], 1, "SPF autoriza emisores, DKIM firma y DMARC aplica política/alineación."),
    ("web", "La defensa principal frente a SQL injection es:", ["Ocultar el SSID", "Consultas parametrizadas", "Filtrar MAC", "Un SAI"], 1, "Las consultas parametrizadas separan los datos del código SQL."),
    ("web", "En XSS almacenado, el contenido malicioso:", ["Solo existe en la URL", "Se guarda y afecta a visitantes posteriores", "Modifica ARP", "Agota DHCP"], 1, "La aplicación lo persiste y lo devuelve a otros navegadores sin neutralizarlo."),
    ("certificados", "Al validar un certificado NO basta con comprobar:", ["La firma de la CA", "La vigencia", "El nombre del sitio", "El color del candado"], 3, "El candado indica una conexión HTTPS válida, no que el sitio sea ético o fiable."),
    ("wifi", "En una empresa, la opción adecuada para credenciales individuales es:", ["SSID oculto", "WEP", "WPA2/WPA3-Enterprise con 802.1X y RADIUS", "Portal cautivo sin cifrado"], 2, "Enterprise permite identidad por usuario y RADIUS centraliza AAA."),
    ("wifi", "Un Evil Twin es:", ["Un AP no autorizado sin imitar una red", "Un AP falso que imita al legítimo", "Un error de DNS", "Un tipo de RAID"], 1, "El Evil Twin copia nombre/aspecto de una WLAN para engañar o hacer MitM."),
    ("monitorizacion", "La diferencia esencial entre IDS e IPS es que:", ["IPS puede bloquear o descartar", "IDS bloquea e IPS registra", "IDS solo sirve para Wi-Fi", "No existe diferencia"], 0, "Un IDS detecta/alerta; un IPS además puede actuar para prevenir."),
    ("monitorizacion", "La detección por anomalías tiene como principal inconveniente:", ["No detecta ataques conocidos", "Falsos positivos", "No analiza red", "No genera alertas"], 1, "Detecta desviaciones nuevas, pero un comportamiento legítimo inusual puede parecer ataque."),
    ("display", "Filtro de visualización para tráfico donde participe 192.168.1.10:", ["host 192.168.1.10", "ip.addr == 192.168.1.10", "ip host 192.168.1.10", "ether host 192.168.1.10"], 1, "En display filters se usa el campo ip.addr con ==."),
    ("display", "Filtro de visualización para ARP Request:", ["arp.opcode == 1", "arp[0] == 1", "arp request", "ether arp"], 0, "Wireshark expone el campo arp.opcode; 1 corresponde a request."),
    ("display", "Para excluir por completo la IP 80.58.32.97 en un filtro de visualización usarías:", ["ip.addr != 80.58.32.97", "!(ip.addr == 80.58.32.97)", "not host 80.58.32.97", "ip not 80.58.32.97"], 1, "La negación envuelve la coincidencia completa; != puede dar resultados engañosos en campos repetidos."),
    ("display", "Filtro de visualización para ICMP Time Exceeded:", ["icmp.type == 8", "icmp.type == 0", "icmp.type == 11", "icmp[0] == 11"], 2, "En visualización se usa icmp.type; el tipo 11 es Time Exceeded."),
    ("captura", "Filtro de captura BPF para guardar solo ICMP:", ["icmp", "icmp.type == 8", "ip.proto == icmp", "icmp[0] == 8 or icmp[0] == 0"], 0, "`icmp` es BPF y captura todos los mensajes ICMP."),
    ("captura", "Filtro de captura para todo tráfico IP de tu equipo:", ["ip.addr == <MI_IP>", "ip and host <MI_IP>", "host == <MI_IP>", "ip.host <MI_IP>"], 1, "BPF usa `host`; `ip.addr` es sintaxis de visualización."),
    ("captura", "Filtro BPF para TCP con SYN activo, incluso SYN+ACK:", ["tcp[13] == 2", "tcp.flags.syn == 1", "tcp[13] & 2 != 0", "tcp.syn"], 2, "La máscara binaria comprueba que el bit SYN está a 1 aunque haya otros flags."),
    ("captura", "Filtro BPF para paquetes TCP con solo SYN, sin ACK u otros flags:", ["tcp[13] == 2", "tcp[13] & 2 != 0", "tcp.port == 2", "tcp.syn == 2"], 0, "El byte de flags vale exactamente 2 cuando únicamente SYN está activo."),
    ("captura", "Filtro BPF para ICMP Echo Request:", ["icmp.type == 8", "icmp[0] == 8", "icmp.request", "ip.icmp == 8"], 1, "BPF consulta directamente el primer byte de ICMP, que contiene el tipo."),
    ("captura", "Filtro BPF para IPv4 con el bit DF activado:", ["ip.df == 1", "ip[6:2] & 0x4000 != 0", "ip.flags.df", "not ip fragment"], 1, "El flag Don't Fragment ocupa el bit 0x4000 del campo flags/fragment offset."),
]

# Banco adicional: preguntas cortas de examen sobre pilares, ataques y mitigaciones.
QUESTIONS.extend([
    ("pilares", "La modificación no autorizada de información afecta a:", ["Integridad", "Disponibilidad", "Confidencialidad", "Fiabilidad"], 0, "Modificar datos sin permiso vulnera la integridad."),
    ("pilares", "Interrumpir un servicio para que nadie pueda usarlo afecta a:", ["No repudio", "Disponibilidad", "Autenticación", "Confidencialidad"], 1, "La interrupción es un ataque contra la disponibilidad."),
    ("pilares", "Obtener datos sin cambiar nada es una:", ["Fabricación", "Intercepción", "Modificación", "Interrupción"], 1, "La intercepción es pasiva y compromete confidencialidad."),
    ("pilares", "Crear un mensaje falso que parece legítimo es:", ["Intercepción", "Fabricación", "Disponibilidad", "Hash"], 1, "Fabricación es crear datos falsos que aparentan ser auténticos."),
    ("malware", "Un acceso remoto oculto y persistente es un:", ["Backdoor", "Gusano", "SAI", "Hash"], 0, "Un backdoor permite volver a entrar sin el flujo normal de acceso."),
    ("malware", "Malware que cifra datos y exige pago:", ["Spyware", "Ransomware", "Adware", "Virus de arranque"], 1, "Ransomware bloquea o cifra datos para exigir un rescate."),
    ("fisica", "Temperatura o polvo excesivos son amenazas:", ["Lógicas", "Físicas", "Criptográficas", "De autenticación"], 1, "Afectan físicamente al equipamiento y su vida útil."),
    ("raid", "RAID 5 usa:", ["Espejo simple", "Paridad distribuida", "Doble espejo", "Solo striping"], 1, "RAID 5 reparte datos y paridad entre discos."),
    ("raid", "RAID 1 se basa en:", ["Paridad", "Striping", "Espejo", "Compresión"], 2, "RAID 1 mantiene copias idénticas en discos espejo."),
    ("raid", "¿Qué RAID tolera dos fallos de disco?", ["RAID 0", "RAID 1", "RAID 5", "RAID 6"], 3, "RAID 6 usa doble paridad y tolera dos discos fallidos."),
    ("copias", "RAID no sustituye una copia porque no protege frente a:", ["Borrado accidental", "Lectura rápida", "Cambio de MAC", "Uso de TLS"], 0, "Una réplica RAID puede replicar borrados, corrupción o ransomware."),
    ("redes", "ARP relaciona en una LAN:", ["IP y MAC", "DNS e IP", "Usuario y contraseña", "Puerto y proceso"], 0, "ARP resuelve la MAC correspondiente a una dirección IPv4 local."),
    ("redes", "ARP spoofing puede usarse para realizar:", ["MitM", "RAID", "Backup", "Cifrado"], 0, "Al desviar tráfico mediante ARP falso se puede interceptar o modificar como intermediario."),
    ("redes", "Control de switch que limita MAC por puerto:", ["Port Security", "DNSSEC", "DMARC", "VPN"], 0, "Port Security reduce MAC flooding y conexiones no esperadas."),
    ("redes", "SPF indica:", ["Servidores autorizados para enviar correo", "Claves Wi-Fi", "Puertos TCP", "Discos RAID"], 0, "SPF publica qué servidores pueden emitir para un dominio."),
    ("redes", "DKIM protege principalmente:", ["La integridad del correo", "El RAID", "La energía", "La MAC"], 0, "DKIM añade una firma verificable del dominio al mensaje."),
    ("web", "En XSS, la medida esencial al mostrar datos de usuario es:", ["Codificar la salida", "Desactivar DNS", "Usar RAID", "Cambiar SSH"], 0, "La codificación de salida evita que el navegador interprete los datos como código."),
    ("credenciales", "Un hash de contraseña se debe:", ["Descifrar", "Comparar", "Enviar por correo", "Publicar"], 1, "Un hash no se descifra; se deriva de nuevo y se compara."),
    ("certificados", "Un certificado vincula una identidad con:", ["Una clave pública", "Una MAC", "Un disco", "Una VLAN"], 0, "El certificado, firmado por una CA, vincula identidad y clave pública."),
    ("wifi", "Ocultar el SSID es una medida:", ["De seguridad fuerte", "Auxiliar, fácil de observar", "Equivalente a WPA3", "Que cifra el tráfico"], 1, "El SSID aparece en tráfico de gestión; no sustituye cifrado ni autenticación robustos."),
    ("wifi", "Filtrar direcciones MAC no es una defensa fuerte porque:", ["Las MAC pueden suplantarse", "No existe en switches", "Cifra poco", "Impide WPA3"], 0, "Una MAC se puede observar y falsificar fácilmente."),
    ("wifi", "WPA3-Personal usa preferentemente:", ["SAE", "WEP", "TKIP", "FTP"], 0, "WPA3-Personal incorpora SAE para el intercambio/autenticación."),
    ("wifi", "RADIUS centraliza:", ["AAA", "RAID", "DNS", "HTTP"], 0, "AAA significa autenticación, autorización y contabilidad."),
    ("monitorizacion", "Un HIDS vigila principalmente:", ["Actividad de un host", "Todo Internet", "Solo routers", "Baterías del SAI"], 0, "HIDS es Host-based IDS; analiza eventos y actividad local del equipo."),
    ("monitorizacion", "Un NIDS analiza principalmente:", ["Tráfico de red", "Solo ficheros locales", "Una CA", "RAID"], 0, "NIDS es Network-based IDS y observa comunicaciones de la red."),
    ("display", "En Wireshark, el filtro para todo tráfico de una MAC es:", ["eth.addr == <MAC>", "ether host <MAC>", "mac host <MAC>", "eth.host <MAC>"], 0, "`eth.addr` es un campo de visualización; `ether host` es BPF de captura."),
    ("display", "En display filter, el tráfico entre dos IP se expresa con:", ["ip.addr == <IP1> && ip.addr == <IP2>", "host <IP1> and host <IP2>", "ip net <IP1>", "src host <IP1>"], 0, "Usar ip.addr para ambas IP cubre ambos sentidos de la conversación."),
    ("captura", "En BPF, para capturar ARP se usa:", ["arp", "arp.opcode == 1", "eth.type == arp", "ip.arp"], 0, "`arp` es el filtro de captura directo para todo tráfico ARP."),
    ("captura", "En BPF, para excluir tráfico de una IP se usa:", ["not host <IP>", "!(ip.addr == <IP>)", "ip.addr != <IP>", "no ip <IP>"], 0, "BPF usa host y operadores lógicos como not."),
    ("captura", "En BPF, el TTL IPv4 se consulta con:", ["ip[8]", "ip.ttl", "ttl", "ip.ttl[8]"], 0, "En el encabezado IPv4, el byte 8 contiene el TTL; ip.ttl es display filter."),
    ("captura", "Un capture filter se aplica:", ["Antes de guardar paquetes", "Después de abrir el PCAP", "Solo para colorear", "Solo en estadísticas"], 0, "Lo no capturado no se puede recuperar posteriormente."),
])

# Segunda ampliación: repasos fáciles para hacer rondas largas sin repetir pronto.
QUESTIONS.extend([
    ("pilares", "Mantener un servicio funcionando como fue diseñado es:", ["Fiabilidad", "Interceptación", "No repudio", "Spoofing"], 0, "La fiabilidad indica que el sistema cumple correctamente la función para la que fue diseñado."),
    ("pilares", "¿Qué propiedad se protege con cifrado y control de acceso?", ["Confidencialidad", "Disponibilidad", "Paridad", "Redundancia"], 0, "El cifrado y las ACL limitan el acceso a información autorizada."),
    ("riesgo", "Un cortafuegos configurado correctamente es un:", ["Control de seguridad", "Ataque", "Impacto", "Activo malicioso"], 0, "Es una salvaguarda o control que reduce exposición a amenazas."),
    ("vulnerabilidades", "OpenVAS y Nessus sirven para:", ["Analizar vulnerabilidades", "Cifrar correo", "Crear RAID", "Reemplazar copias"], 0, "Ambos son escáneres que detectan fallos, servicios y configuraciones inseguras."),
    ("vulnerabilidades", "Un hallazgo de un escáner debe:", ["Corregirse sin revisar", "Interpretarse según exposición e impacto", "Publicarse siempre", "Ignorarse si es bajo"], 1, "Un hallazgo necesita contexto: activo expuesto, impacto y corrección disponible."),
    ("malware", "Un virus suele necesitar:", ["Un fichero o ejecución que lo active", "Una CA", "Un SAI", "Un cable Ethernet"], 0, "El virus se asocia a un archivo o ejecución; el gusano se replica solo."),
    ("malware", "Una botnet es:", ["Un conjunto coordinado de equipos infectados", "Un switch con muchas MAC", "Una red VPN", "Una copia incremental"], 0, "Una botnet reúne bots controlados remotamente por un atacante."),
    ("fisica", "El SAI aporta principalmente:", ["Energía temporal y protección ante fallos eléctricos", "Cifrado web", "Detección de XSS", "Paridad RAID"], 0, "El SAI mantiene alimentación durante cortes breves y estabiliza según su tipo."),
    ("fisica", "La climatización en una sala de servidores ayuda frente a:", ["Temperatura y aire inadecuado", "SQL injection", "ARP spoofing", "Phishing"], 0, "Temperatura, polvo y humedad son amenazas físicas de los equipos."),
    ("continuidad", "Después de un incidente, restaurar sistemas y documentar corresponde a:", ["Recuperación", "Reconocimiento", "Fabricación", "Escaneo"], 0, "La recuperación se produce después de la emergencia y restaura la operación."),
    ("cripto", "El cifrado simétrico es adecuado para:", ["Mucho volumen de datos", "Firmar documentos", "Evitar DoS", "Descubrir puertos"], 0, "Es rápido, aunque requiere intercambio y gestión segura de la clave compartida."),
    ("cripto", "La principal limitación del cifrado simétrico es:", ["Intercambio y gestión de claves", "Que no usa clave", "Que siempre es lento", "Que no cifra datos"], 0, "Los participantes deben compartir de forma segura la misma clave secreta."),
    ("cripto", "La clave privada debe:", ["Mantenerse secreta", "Publicarse en DNS", "Compartirse con todos", "Usarse como MAC"], 0, "La seguridad asimétrica depende de que la clave privada no se divulgue."),
    ("acceso", "Una ACL define:", ["Reglas de permisos o acceso", "Tipo de malware", "Paridad de RAID", "Un protocolo Wi-Fi"], 0, "Una lista de control de acceso establece qué sujetos pueden acceder a qué recursos."),
    ("biometria", "En biometría, el template es:", ["Patrón almacenado para comparar", "Una contraseña temporal", "Una MAC de red", "Un certificado"], 0, "El template representa el rasgo biométrico registrado y se compara en la verificación."),
    ("forense", "La evidencia forense debe protegerse para mantener su:", ["Integridad", "Latencia", "Cobertura Wi-Fi", "Capacidad RAID"], 0, "Si una evidencia se altera sin control, pierde fiabilidad y posible validez legal."),
    ("forense", "Un ejemplo de evidencia digital es:", ["Logs", "Solo papel impreso", "Un SAI", "Un SSID"], 0, "También pueden ser memoria, tráfico, metadatos, discos o ficheros."),
    ("ataques", "La primera fase típica de un ataque es:", ["Reconocimiento", "Borrado de huellas", "Persistencia", "Recuperación"], 0, "Antes de acceder, un atacante recopila información sobre el objetivo."),
    ("ataques", "Mantener acceso para volver a entrar corresponde a:", ["Persistencia", "Intercepción", "Disponibilidad", "Paridad"], 0, "Tras el acceso, se buscan mecanismos para mantenerlo o repetirlo."),
    ("ataques", "Una auditoría autorizada termina con:", ["Un informe", "Un rescate", "El borrado de servidores", "Una clave privada pública"], 0, "La auditoría documenta resultados, riesgos y recomendaciones en un informe."),
    ("ataques", "OSINT consiste en:", ["Recoger información pública", "Cifrar discos", "Bloquear puertos", "Crear certificados"], 0, "OSINT usa fuentes abiertas para conocer la exposición o contexto de un objetivo."),
    ("redes", "IP Source Guard ayuda a impedir:", ["IP/MAC no autorizadas", "Cortes eléctricos", "XSS", "RAID 0"], 0, "Comprueba asociaciones válidas de IP y MAC, normalmente junto a DHCP Snooping."),
    ("redes", "SMTP spoofing consiste en falsificar:", ["El remitente de correo", "Una IP de DNS", "Una clave Wi-Fi", "El TTL"], 0, "El remitente visible del correo puede falsificarse; SPF/DKIM/DMARC ayudan a combatirlo."),
    ("redes", "Un MitM puede:", ["Observar o modificar comunicación entre extremos", "Solo apagar equipos", "Solo crear backups", "Solo firmar certificados"], 0, "Un intermediario malicioso puede ser pasivo o modificar tráfico activamente."),
    ("web", "Nikto se usa principalmente para:", ["Detectar indicios de problemas en servidores web", "Cifrar HTTP", "Configurar RAID", "Analizar baterías"], 0, "Nikto es un escáner web; sus hallazgos se validan antes de remediar."),
    ("web", "El principio de mínimo privilegio para una BD significa:", ["Dar solo permisos necesarios", "Dar permisos de administrador", "Eliminar usuarios", "Usar una sola contraseña"], 0, "Limitar permisos reduce daño si una aplicación sufre SQL injection."),
    ("credenciales", "Rate limiting ayuda frente a:", ["Fuerza bruta en línea", "Robo físico", "RAID 6", "Cortes eléctricos"], 0, "Limitar intentos ralentiza ataques de contraseñas contra servicios en línea."),
    ("credenciales", "Un keylogger intenta:", ["Registrar pulsaciones", "Aumentar TTL", "Firmar DNS", "Hacer striping"], 0, "Un keylogger roba credenciales y otros datos al registrar teclas."),
    ("certificados", "La revocación de un certificado es relevante cuando:", ["Su clave privada se compromete", "Se instala un SAI", "Se usa RAID", "Se oculta SSID"], 0, "Un certificado comprometido debe revocarse y sustituirse."),
    ("publicas", "HTTPS se basa actualmente en:", ["TLS", "ARP", "WEP", "FTP"], 0, "HTTPS usa TLS para confidencialidad, integridad y autenticación web."),
    ("publicas", "El candado del navegador NO garantiza:", ["Que el sitio sea ético", "Que TLS está establecido", "Que la conexión se cifra", "Que el certificado se validó"], 0, "Un sitio fraudulento también puede tener HTTPS válido."),
    ("wifi", "Un Rogue AP es:", ["Punto de acceso no autorizado", "Un AP falso que imita una red", "Una CA", "Un SAI"], 0, "Rogue AP es cualquier punto no autorizado; Evil Twin además imita al legítimo."),
    ("wifi", "Separar invitados de la red interna aporta:", ["Segmentación", "Paridad", "No repudio", "Un hash"], 0, "Una red de invitados separada limita el movimiento hacia sistemas internos."),
    ("monitorizacion", "Un filtro de captura puede usar:", ["host 192.168.1.10", "ip.addr == 192.168.1.10", "eth.addr == xx", "tcp.dstport == 80"], 0, "BPF usa host; los campos con puntos son de visualización."),
    ("display", "Un filtro de visualización para todo tráfico DNS puede ser:", ["dns", "port 53", "src port 53", "udp[53]"], 0, "`dns` usa el disector Wireshark y muestra consultas y respuestas DNS interpretadas."),
    ("display", "Para ver paquetes ICMP con TTL inferior a 10 se puede usar:", ["icmp && ip.ttl < 10", "icmp[0] < 10", "ttl < 10", "ip[8] < 10"], 0, "En visualización se combinan campos Wireshark: icmp e ip.ttl."),
    ("captura", "En BPF, para tráfico entre dos MAC se usa:", ["ether host <MAC1> and ether host <MAC2>", "eth.addr == <MAC1> && eth.addr == <MAC2>", "mac pair", "ether pair"], 0, "Cada `ether host` acepta origen o destino; con and se selecciona la conversación entre ambas."),
    ("captura", "En BPF, para TCP o UDP se puede escribir:", ["tcp or udp", "tcp || udp", "tcp/udp", "transport"], 0, "BPF usa operadores lógicos escritos como and, or y not."),
    ("captura", "El filtro BPF para todos los paquetes TCP es:", ["tcp", "tcp.port", "ip.tcp", "tcp == true"], 0, "El identificador de protocolo `tcp` captura todos los segmentos TCP."),
])

# Tercera ampliación: teoría general y ataques, sin repetir Wireshark.
QUESTIONS.extend([
    ("pilares", "La confidencialidad busca que accedan a los datos:", ["Solo entidades autorizadas", "Todos los usuarios", "Solo administradores físicos", "Solo switches"], 0, "La confidencialidad limita el acceso a quienes están autorizados."),
    ("pilares", "La autenticación responde a la pregunta:", ["¿Quién eres?", "¿Qué permisos tienes?", "¿Cuánto espacio queda?", "¿Qué RAID usas?"], 0, "Primero se verifica identidad; después la autorización decide permisos."),
    ("pilares", "La autorización decide:", ["Qué puede hacer una identidad ya autenticada", "Quién es el usuario", "Si existe TLS", "Qué IP tiene el equipo"], 0, "La autorización controla privilegios y acceso a recursos."),
    ("riesgo", "Un activo puede ser:", ["Datos, personas, hardware o servicios", "Solo un servidor físico", "Solo una contraseña", "Solo un programa malicioso"], 0, "Todo recurso valioso para la organización puede ser un activo."),
    ("riesgo", "Antes de aplicar controles, conviene primero:", ["Inventariar activos y analizar riesgos", "Instalar todos los antivirus", "Borrar logs", "Ocultar SSID"], 0, "La gestión de riesgos comienza identificando qué se protege y sus amenazas."),
    ("malware", "Adware es software que:", ["Muestra publicidad y puede rastrear", "Cifra archivos", "Da acceso remoto", "Hace paridad"], 0, "Adware se centra en publicidad, aunque puede incluir seguimiento."),
    ("malware", "Un stealer está orientado a:", ["Robar credenciales e información", "Dar energía", "Hacer backups", "Filtrar paquetes"], 0, "Los stealers buscan datos de navegadores, cuentas o credenciales."),
    ("fisica", "La detección y extinción de incendios protege frente a:", ["Pérdida física de equipos y datos", "XSS", "DNS spoofing", "Fuerza bruta"], 0, "El incendio es una amenaza física con impacto grave."),
    ("fisica", "Un corte eléctrico puede mitigarse con:", ["SAI y grupo electrógeno", "Solo una ACL", "Solo MFA", "DNSSEC"], 0, "El SAI cubre transición; el generador prolonga autonomía."),
    ("copias", "Una copia de seguridad se usa para:", ["Recuperar datos", "Aumentar puertos", "Autenticar usuarios", "Firmar correos"], 0, "El objetivo de una copia es poder restaurar información tras pérdida o daño."),
    ("copias", "La recuperación lógica se refiere normalmente a:", ["Ficheros o particiones", "Reparar un disco físicamente", "Cifrar una VPN", "Configurar Wi-Fi"], 0, "La lógica trabaja con estructuras de datos; la física con soportes dañados."),
    ("forense", "Una metodología forense correcta incluye:", ["Preservar, analizar y documentar", "Modificar el original", "Borrar logs", "Reiniciar sin recopilar"], 0, "Preservación, cadena de custodia, análisis reproducible e informe son esenciales."),
    ("auditoria", "Una auditoría parcial analiza:", ["Un ámbito concreto", "Toda la organización obligatoriamente", "Solo malware", "Solo discos"], 0, "La completa ofrece visión global; la parcial se limita a un ámbito definido."),
    ("redes", "MAC flooding pretende:", ["Saturar la tabla MAC del switch", "Agotar direcciones IP DHCP", "Modificar DNS", "Cifrar tráfico"], 0, "Al llenar la tabla MAC, puede favorecer difusión de tráfico según el switch."),
    ("redes", "¿Cuál NO cifra la navegación web?", ["DNSSEC", "HTTPS", "VPN", "TLS"], 0, "DNSSEC autentica datos DNS; HTTPS/TLS y VPN protegen el canal de datos."),
    ("redes", "Una defensa contra ARP spoofing es:", ["Segmentación y cifrado extremo a extremo", "WEP", "RAID 0", "Ocultar SSID"], 0, "Controles ARP ayudan, pero cifrado E2E reduce el valor de interceptar tráfico."),
    ("web", "Un error detallado de base de datos puede facilitar:", ["SQL injection", "RAID", "SAI", "WPA3"], 0, "Los errores reveladores ayudan a conocer estructura y consultas."),
    ("web", "En una subida de archivos, confiar solo en la extensión es:", ["Inseguro", "Suficiente", "Obligatorio", "Un cifrado"], 0, "Hay que validar tipo real, tamaño y almacenamiento; la extensión se manipula."),
    ("credenciales", "Phishing busca sobre todo:", ["Engañar para obtener datos o credenciales", "Aumentar disponibilidad", "Crear paridad", "Analizar malware"], 0, "Es ingeniería social mediante suplantación de una entidad confiable."),
    ("credenciales", "Una contraseña recomendable debe ser:", ["Larga, única y no predecible", "Corta y común", "La misma en todos los servicios", "El nombre de usuario"], 0, "Longitud y unicidad reducen fuerza bruta, diccionarios y reutilización."),
    ("certificados", "Una PKI incluye:", ["CA, certificados, normas y confianza", "Solo una contraseña", "Solo un firewall", "Solo un router"], 0, "PKI es la infraestructura que gestiona emisión, confianza y ciclo de vida de certificados."),
    ("wifi", "WPA2 usa normalmente:", ["AES-CCMP", "WEP", "Solo TKIP", "ARP"], 0, "WPA2 con AES/CCMP sigue siendo alternativa cuando WPA3 no es posible."),
    ("wifi", "En WPA-Enterprise se puede revocar acceso de:", ["Un usuario concreto", "Solo todos los usuarios a la vez", "Nadie", "Un disco RAID"], 0, "Las credenciales individuales permiten revocación y auditoría por usuario."),
    ("wifi", "El estándar 802.1X proporciona:", ["Control de acceso mediante autenticación", "Paridad distribuida", "Cifrado de discos", "Resolución DNS"], 0, "802.1X controla el acceso a red tras autenticar al solicitante."),
    ("monitorizacion", "La captura de tráfico proporciona:", ["Detalle de comunicaciones concretas", "Solo una alerta general", "Cifrado automático", "Copias de seguridad"], 0, "Capturar paquetes permite inspección detallada de protocolos y conversaciones."),
    ("monitorizacion", "La detección por firmas falla especialmente ante:", ["Ataques nuevos o variantes", "Ataques conocidos", "Logs", "Paquetes TCP"], 0, "Las firmas requieren conocer previamente el patrón a detectar."),
    ("ataques", "Fingerprinting busca identificar con precisión:", ["Sistemas y servicios", "Solo usuarios", "Baterías", "Copias"], 0, "Tras el reconocimiento, fingerprinting perfila sistemas, versiones y servicios."),
    ("ataques", "La explotación de una vulnerabilidad en auditoría debe ser:", ["Controlada y autorizada", "Siempre pública", "Sin informar", "Contra cualquier objetivo"], 0, "En una auditoría se valida de forma controlada y dentro del alcance autorizado."),
    ("correo", "DMARC añade principalmente:", ["Política, alineación e informes", "Cifrado de disco", "Paridad", "Control Wi-Fi"], 0, "DMARC coordina SPF/DKIM y define qué hacer con mensajes que fallan."),
    ("correo", "PGP y S/MIME se usan para proteger:", ["Mensajes de correo", "RAID", "Tablas MAC", "SAI"], 0, "Ambos aplican criptografía de clave pública al correo electrónico."),
    ("publicas", "En una red pública, una VPN reduce el riesgo de:", ["Intercepción en la red no confiable", "Fallo de un disco", "SQL injection por sí sola", "Incendio"], 0, "La VPN crea un túnel protegido, aunque no elimina todos los riesgos del endpoint."),
    ("publicas", "SSH debe preferirse frente a Telnet porque:", ["Cifra la administración remota", "Usa RAID", "No usa autenticación", "Solo funciona en Wi-Fi"], 0, "Telnet transmite en claro; SSH protege canal y autenticación."),
    ("pilares", "Si se altera un log para ocultar un acceso, se ataca la:", ["Integridad", "Disponibilidad", "Fiabilidad", "Energía"], 0, "Alterar un registro compromete que represente fielmente lo ocurrido."),
    ("pilares", "Un mensaje falso enviado como si fuera el administrador es:", ["Fabricación", "Intercepción", "Copia", "Recuperación"], 0, "Se crea información fraudulenta que aparenta proceder de otra entidad."),
    ("riesgo", "El impacto de un ataque puede ser:", ["Pérdida económica o de datos", "Solo una IP", "Un hash", "Una MAC"], 0, "Impacto es la consecuencia o daño resultante del incidente."),
])

# Variantes de recuerdo activo: repiten conceptos clave con las opciones rotadas.
# Sirven para ampliar simulacros sin asociar una respuesta a una letra fija.
for review_index in range(65):
    category, text, options, answer, explanation = QUESTIONS[review_index]
    shift = (review_index % 3) + 1
    rotated_options = options[shift:] + options[:shift]
    rotated_answer = (answer - shift) % len(options)
    QUESTIONS.append((
        category,
        f"Repaso rápido: {text}",
        rotated_options,
        rotated_answer,
        explanation,
    ))

def public_question(index):
    category, text, options, _, _ = QUESTIONS[index]
    return {"id": index, "category": category, "text": text, "options": options}

def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"round": [], "answers": [], "finished": False}

def save_state(state):
    DATA_DIR.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2))

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def send_json(self, status, value):
        data = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(data)); self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        if urlparse(self.path).path == "/api/state":
            state = load_state()
            answered = len(state["answers"])
            questions = [public_question(i) for i in state["round"]]
            self.send_json(200, {"state": state, "questions": questions, "answered": answered})
            return
        return super().do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or "{}")
        route = urlparse(self.path).path
        if route == "/api/new-round":
            size = min(int(body.get("size", 10)), len(QUESTIONS))
            # Durante esta fase de estudio se prioriza teoría; Wireshark queda aparte.
            order = [i for i, question in enumerate(QUESTIONS) if question[0] not in {"display", "captura"}]
            random.SystemRandom().shuffle(order)
            size = min(size, len(order))
            state = {"round": order[:size], "answers": [], "finished": False}
            save_state(state); self.send_json(200, {"ok": True}); return
        if route == "/api/answer":
            state = load_state(); position = int(body.get("position", -1)); selected = int(body.get("selected", -1))
            if position != len(state["answers"]) or position >= len(state["round"]) or selected not in range(4):
                self.send_json(400, {"error": "Respuesta no válida"}); return
            question = QUESTIONS[state["round"][position]]
            correct = selected == question[3]
            state["answers"].append({"question_id": state["round"][position], "selected": selected, "correct": correct})
            state["finished"] = len(state["answers"]) == len(state["round"])
            save_state(state)
            self.send_json(200, {"correct": correct, "answer": question[3], "explanation": question[4], "finished": state["finished"]}); return
        self.send_json(404, {"error": "No encontrado"})

if __name__ == "__main__":
    print("Entrenador SAD disponible en http://127.0.0.1:8765")
    ThreadingHTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
