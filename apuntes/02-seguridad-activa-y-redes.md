# UD02 - Seguridad activa, ataques y redes

## Manual, ataque y auditoría

El manual de seguridad fija normas, responsabilidades y respuesta. Debe involucrar departamentos, contemplar personas/tecnología/legislación, aprobarse y comunicarse. Medidas diarias: parches, antimalware, firewall, copias verificadas, mínimo privilegio, formación y registros.

```text
Ataque: reconocimiento -> exploración -> acceso -> persistencia -> borrado de huellas
Auditoría autorizada: footprinting -> fingerprinting -> análisis -> validación controlada -> informe
```

OSINT y buscadores revelan exposición pública. Defensa: inventario, cerrar servicios innecesarios, eliminar datos expuestos y parchear.

## Ataques de red: impacto y defensa

| Ataque | Efecto | Defensas |
|---|---|---|
| Sniffing | captura pasiva de paquetes | TLS/HTTPS, SSH/VPN, segmentación |
| MAC flooding | satura tabla MAC; puede difundir tráfico | Port Security, 802.1X, límite de MAC |
| ARP spoofing/MitM | falsea IP-MAC e intercepta | validación ARP, segmentación, cifrado E2E |
| IP spoofing | falsifica IP origen | filtros ingress/egress; DHCP Snooping + IP Source Guard |
| DNS spoofing | DNS da IP falsa | DNSSEC, resolutor fiable, TLS |
| SMTP spoofing | remitente de correo falso | SPF + DKIM + DMARC |
| Rogue DHCP | entrega configuración falsa | DHCP Snooping, puertos confiables |
| DHCP starvation | agota direcciones disponibles | Snooping, Port Security/rate limit |

En switch, una tabla MAC reenvía normalmente solo al puerto destino, por eso dificulta sniffing frente a un hub. En Wi-Fi la señal puede capturarse dentro de alcance, pero cifrado robusto impide interpretar su contenido.

```text
ARP spoofing: ARP falso -> víctima asocia gateway con MAC atacante
-> tráfico pasa por atacante -> reenvía (pasivo) o modifica (activo)

DNS normal: cliente -> DNS -> IP auténtica -> servidor legítimo
DNS falso:   cliente -> respuesta manipulada -> IP atacante -> web imitada
```

DNSSEC autentica y protege integridad de datos DNS; no cifra navegación.

| Correo | Función |
|---|---|
| SPF | lista servidores autorizados a enviar por dominio |
| DKIM | firma de dominio e integridad del mensaje |
| DMARC | política, alineación SPF/DKIM e informes |

## Aplicaciones web

| Vulnerabilidad | Qué ocurre | Prevención |
|---|---|---|
| SQL injection | entrada se interpreta como SQL | consultas parametrizadas, validación, mínimo privilegio BD, errores no detallados |
| XSS reflejado | entrada vuelve en respuesta y navegador la ejecuta | validar y codificar salida, CSP |
| XSS almacenado | contenido se guarda y afecta a visitantes | lo anterior + saneamiento persistente |
| Subida insegura | ejecutables, tamaño excesivo o rutas manipuladas | tipo real/lista permitida, límites, renombrar, fuera de zona ejecutable |

En XSS, validar entrada y **codificar/escapar salida según el contexto**. El servidor debe validar: se puede manipular o saltar el cliente. Escáneres como Nikto descubren indicios; hay que validar y remediar hallazgos.

## Contraseñas y autenticación

| Riesgo | Defensa |
|---|---|
| fuerza bruta/diccionario | contraseña larga/única, rate limiting, MFA, KDF lenta |
| phishing | formación, verificación de dominio, MFA |
| keylogger | endpoint protegido y MFA |
| hashes filtrados | salt único y KDF lenta; nunca texto claro |

```text
Saber: contraseña/PIN | Tener: token, móvil, certificado | Ser: biometría
MFA = factores de categorías distintas.

Registro: contraseña -> salt único -> KDF -> guardar salt + hash + parámetros
Login: recuperar salt/parámetros -> misma KDF -> comparar -> permitir/denegar
```

El **salt** evita hashes iguales ante contraseñas iguales y reduce rainbow tables. Un hash se compara; no se descifra.

## Certificados y redes públicas

| Elemento | Aporta | No aporta solo |
|---|---|---|
| Firma digital | integridad, autenticidad, autoría/no repudio | confidencialidad |
| Certificado | identidad vinculada a clave pública, firmado por CA | cifrado automático del contenido |
| PKI | emisión, confianza y revocación de certificados | seguridad ante clave privada filtrada |

Validar certificado: firma CA, vigencia, identidad/nombre, revocación y cadena confiable.

| Tecnología | Propósito |
|---|---|
| SSH | administración remota cifrada |
| VPN | túnel protegido en red no confiable |
| HTTPS/TLS | confidencialidad, integridad y autenticación web |

El candado indica HTTPS correctamente establecido, no que el sitio sea ético/fiable.

## Wi-Fi

| Mecanismo | Estado |
|---|---|
| WEP | obsoleto/inseguro |
| WPA/TKIP | obsoleto |
| WPA2 | AES-CCMP; opción de compatibilidad |
| WPA3 | preferible; SAE en Personal |
| WPA2/3-Enterprise | 802.1X/EAP e identidad individual |

SSID oculto y filtrado MAC son auxiliares: se observan/suplantan. Actualizar AP, desactivar WPS si no se usa, separar invitados, segmentar y detectar AP no autorizados.

```text
Rogue AP = punto no autorizado.
Evil Twin = AP falso que imita el legítimo -> posible portal falso/MitM.
Defensa: WPA3 o Enterprise, validar certificados/red, segmentación y monitorización.

Supplicant (cliente) -> Authenticator (AP/switch) -> RADIUS -> identidad
                                        <- valida/autoriza <-
```

WPA-Enterprise evita una clave compartida: credenciales por usuario, revocación individual, registros y directorio. RADIUS centraliza AAA (autenticación, autorización y contabilidad). Un portal cautivo autoriza acceso mediante página; **no cifra** la WLAN.

## Monitorización e intrusiones

| Concepto | Función |
|---|---|
| Captura | detalle de comunicación concreta |
| Monitorización | estado continuo: disponibilidad, CPU, red, latencia y alertas |
| Filtro de captura | elige qué paquetes se almacenan |
| Filtro de visualización | elige qué se muestra de captura ya existente |
| HIDS | actividad sospechosa en un host |
| NIDS | actividad sospechosa en tráfico de red |
| IPS | detecta y puede bloquear/limitar/descartar |

| Método IDS | Ventaja | Riesgo |
|---|---|---|
| Firmas | eficaz frente a ataques conocidos | falla ante novedad/variantes |
| Anomalías | detecta desviaciones nuevas | falsos positivos |

Para practicar los filtros de captura y visualización de los boletines, consulta la [chuleta de Wireshark](05-wireshark-filtros-practica.md).
