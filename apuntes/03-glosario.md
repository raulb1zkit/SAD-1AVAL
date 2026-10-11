# Glosario esencial por bloques

## 1. Fundamentos y gestión del riesgo

| Término | Definición |
|---|---|
| Activo | Recurso con valor que debe protegerse: datos, personas, hardware, software, red o servicio. |
| Amenaza | Circunstancia con capacidad de causar daño a un activo. |
| Vulnerabilidad | Debilidad que una amenaza puede aprovechar. |
| Riesgo | Posibilidad de que una amenaza explote una vulnerabilidad y produzca daño. |
| Ataque | Materialización de una amenaza. |
| Impacto | Daño o consecuencia que deja un ataque. |
| Fiabilidad | El sistema cumple correctamente la función para la que fue diseñado. |
| Confidencialidad | Solo las entidades autorizadas acceden a la información. |
| Integridad | La información no se altera sin autorización. |
| Disponibilidad | Sistemas y datos accesibles cuando se necesitan. |
| Autenticación | Verificación de identidad de una entidad. |
| No repudio | Evidencia que impide negar la autoría o recepción de una operación. |
| ACL | Lista de reglas de acceso/permisos para recursos, usuarios o tráfico. |
| Auditoría | Revisión de controles, cumplimiento y mejoras de seguridad. |
| Análisis forense | Recogida, preservación y análisis de evidencias con validez técnica/legal. |
| Cadena de custodia | Registro de quién recoge, trata y conserva una evidencia. |

## 2. Ataques y técnicas de red

| Término | Definición |
|---|---|
| Interceptación | Captura pasiva de información sin modificarla. |
| Interrupción | Ataque que deja un recurso inaccesible o degradado. |
| Modificación | Alteración no autorizada de información en tránsito o almacenada. |
| Fabricación | Creación de mensajes falsos que aparentan ser legítimos. |
| DoS / DDoS | Denegación de servicio; distribuida cuando participa más de un origen. |
| Sniffing | Captura y análisis de paquetes de red. |
| MAC flooding | Saturación de la tabla MAC de un switch mediante muchas MAC falsas. |
| Spoofing | Suplantación de una identidad, dirección o servicio. |
| ARP spoofing | Falsea la relación IP-MAC para desviar tráfico en una LAN. |
| IP spoofing | Falsea la dirección IP de origen de un paquete. |
| DNS spoofing | Entrega/manipula una respuesta DNS para dirigir a una IP falsa. |
| SMTP spoofing | Envío de correo con un remitente falsificado. |
| MitM | Intermediario que observa o modifica tráfico entre dos extremos. |
| Rogue DHCP | Servidor DHCP no autorizado que da configuración de red falsa. |
| DHCP starvation | Agotamiento de direcciones DHCP mediante solicitudes falsas. |
| Rogue AP | Punto de acceso inalámbrico no autorizado. |
| Evil Twin | Punto de acceso falso que imita una red Wi-Fi legítima. |
| Phishing | Engaño que suplanta una entidad para robar datos o credenciales. |
| Ingeniería social | Manipulación de personas para obtener acceso o información. |

## 3. Malware y análisis

| Término | Definición |
|---|---|
| Malware | Software malicioso o no deseado. |
| Bug | Error de diseño o programación; suele corregirse con un parche. |
| Troyano | Programa que aparenta ser legítimo mientras ejecuta acciones ocultas. |
| Backdoor | Mecanismo de acceso remoto oculto o persistente. |
| Bomba lógica | Código que se activa al cumplirse una condición. |
| Virus | Código que se activa asociado a un archivo o su ejecución. |
| Gusano | Malware que se replica por sí mismo y consume recursos/red. |
| Spyware | Software que recopila datos sin conocimiento del usuario. |
| Stealer | Malware centrado en robar información y credenciales. |
| Adware | Software publicitario que puede rastrear actividad. |
| Ransomware | Malware que bloquea o cifra datos para exigir un rescate. |
| Bot / botnet | Equipo infectado controlado remotamente / conjunto coordinado de bots. |
| Sandbox | Entorno aislado para analizar software sospechoso. |
| Análisis estático | Estudio de un archivo sin ejecutarlo. |
| Análisis dinámico | Observación controlada de su comportamiento al ejecutarlo. |

## 4. Criptografía, identidad y contraseñas

| Término | Definición |
|---|---|
| Cifrado simétrico | Cifrado con una clave secreta compartida; rápido para grandes volúmenes. |
| Cifrado asimétrico | Cifrado basado en par de clave pública y privada. |
| Clave pública | Clave que se puede distribuir para cifrado/verificación. |
| Clave privada | Clave secreta usada para descifrar o firmar. |
| Firma digital | Integridad, autenticidad y evidencia de autoría; no cifra por sí sola. |
| Certificado digital | Documento firmado que vincula una identidad con una clave pública. |
| CA | Autoridad de certificación que firma/gestiona certificados. |
| PKI | Infraestructura de certificados, autoridades, normas y confianza. |
| Hash | Resumen de longitud fija; se compara, no se descifra. |
| Salt | Valor único añadido antes de derivar el hash de una contraseña. |
| KDF | Función lenta y parametrizable que deriva un valor seguro desde contraseña. |
| Rainbow table | Tabla precalculada para relacionar contraseñas posibles con hashes. |
| MFA | Autenticación con factores de categorías distintas: saber, tener y/o ser. |
| Biometría | Identificación mediante rasgos físicos o de comportamiento. |
| SPF | Registro DNS que autoriza servidores de correo de un dominio. |
| DKIM | Firma de correo ligada a dominio que protege integridad. |
| DMARC | Política de correo que coordina/alinea SPF y DKIM. |

## 5. Infraestructura, almacenamiento y continuidad

| Término | Definición |
|---|---|
| SAI / UPS | Sistema que entrega energía temporal al fallar el suministro. |
| Grupo electrógeno | Equipo que genera electricidad con otra fuente, normalmente combustible. |
| RAID | Organización de varios discos para rendimiento, capacidad y/o tolerancia. |
| Striping | Reparto de bloques de datos entre discos. |
| Espejo | Copia idéntica de datos en otro disco. |
| Paridad | Información redundante para reconstruir datos tras un fallo. |
| Copia de seguridad | Copia recuperable de datos. RAID no la sustituye. |
| Imagen de respaldo | Copia de un estado completo para restauración rápida. |
| Plan de contingencia | Respaldo, emergencia y recuperación ante incidente. |

## 6. Acceso, red y monitorización

| Término | Definición |
|---|---|
| ARP | Protocolo que asocia direcciones IP y MAC en una red local. |
| MAC | Dirección física de una interfaz de red. |
| DHCP Snooping | Control de switch que identifica DHCP fiable y asociaciones válidas. |
| IP Source Guard | Bloquea tráfico con IP/MAC no autorizadas según asociaciones válidas. |
| Port Security | Control de switch que limita MAC permitidas por puerto. |
| DNSSEC | Firmas que aportan autenticidad e integridad a datos DNS. |
| TLS / HTTPS | Protección criptográfica de las comunicaciones web. |
| SSH | Administración remota autenticada y cifrada. |
| VPN | Túnel protegido sobre una red no confiable. |
| WPA2 / WPA3 | Seguridad Wi-Fi; WPA3 es preferible. |
| 802.1X | Control de acceso a red por autenticación de puerto. |
| EAP | Marco de autenticación usado habitualmente con 802.1X. |
| RADIUS | Servicio centralizado de autenticación, autorización y contabilidad. |
| Portal cautivo | Página que autoriza acceso a red; no cifra la WLAN. |
| HIDS | IDS que analiza actividad de un host. |
| NIDS | IDS que analiza tráfico de red. |
| IPS | Sistema que detecta y puede bloquear/prevenir. |
| Filtro de captura | Decide qué paquetes se guardan durante la captura. |
| Filtro de visualización | Decide qué se muestra de una captura ya existente. |
