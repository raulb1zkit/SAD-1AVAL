# Modelo de examen Wireshark resuelto

Resolución del modelo A de UD02, parte 3. Distingue siempre el lugar donde escribes el filtro:

- **Visualización**: se aplica a una captura ya realizada y usa campos como `ip.addr`, `tcp.dstport` o `icmp.type`.
- **Captura (BPF)**: se escribe antes de capturar y usa expresiones como `host`, `port`, `icmp[0]` o `tcp[13]`.

## Bloque 1 — Filtros de visualización

### 1. Tramas Ethernet de una MAC sin TCP

> Ver las tramas Ethernet enviadas por `00:16:3c:f1:fd:6d` que no transporten tráfico TCP.

```wireshark
eth.src == 00:16:3c:f1:fd:6d && !tcp
```

`eth.src` expresa «enviadas por»; `!tcp` descarta las que transportan TCP.

### 2. Datagramas intercambiados entre dos IP

> Ver los datagramas IP entre `47.89.158.121` y `198.71.247.91`, en ambos sentidos.

```wireshark
ip.addr == 47.89.158.121 && ip.addr == 198.71.247.91
```

`ip.addr` coincide tanto con origen como con destino.

### 3. Echo Request con origen y destino concretos

> Ver los ICMP Echo Request desde `3.82.113.93` hacia `198.71.247.91`.

```wireshark
icmp.type == 8 && ip.src == 3.82.113.93 && ip.dst == 198.71.247.91
```

`icmp.type == 8` es Echo Request. Echo Reply sería `icmp.type == 0`.

### 4. Mensajes destinados a TCP 8080 de una máquina

> Ver los mensajes destinados al puerto TCP `8080` de `198.71.247.91`.

```wireshark
tcp.dstport == 8080 && ip.dst == 198.71.247.91
```

### 5. HTTP que contenga una palabra

> Ver los mensajes HTTP que contengan `XDEBUG`.

```wireshark
http contains "XDEBUG"
```

### 6. Geolocalización y paquetes procedentes de Rusia

Wireshark necesita las bases de datos **GeoLite2/MaxMind** en formato `.mmdb` (la base City es la habitual; ASN es opcional). Tras instalarlas o descargarlas, se añade la carpeta que las contiene en:

```text
Editar → Preferencias → Name Resolution → MaxMind database directories
```

Después, el filtro para Rusia es:

```wireshark
ip.geoip.country_iso == "RU"
```

Para la evidencia pedida, se filtra, se selecciona un paquete de la lista y se despliega el protocolo IP hasta que sean visibles sus campos `ip.geoip.*` (país, código de país, ciudad o ASN, según la base instalada). La captura se guarda con el nombre solicitado, por ejemplo `nombre_rusia.png`.

## Bloque 2 — Análisis de la captura

Estos dos apartados requieren el fichero `ex_sniffer_01.pcap`, que no acompañaba al modelo. Por ello el porcentaje y el cuerpo concreto no se pueden inventar: en el examen se obtienen así.

### 1. Porcentaje del tráfico ICMP

1. Abrir la captura.
2. Ir a **Estadísticas → Jerarquía de protocolos** (*Statistics → Protocol Hierarchy*).
3. Buscar la fila `ICMP`.
4. Anotar la columna **Percent Packets** / **% Packets**, no el porcentaje de bytes.
5. Hacer una captura en la que aparezcan la fila ICMP, la columna y el porcentaje.

Como comprobación, el filtro `icmp` permite conocer el número de paquetes ICMP mostrados, pero la jerarquía de protocolos es la evidencia más directa para entregar.

### 2. Recuperar el cuerpo del POST a `diag_Form` del paquete 12039

1. Usar **Ir → Ir al paquete** (`Ctrl + G`) y escribir `12039`.
2. Comprobar que corresponde a una petición `POST` a `diag_Form`.
3. Clic derecho → **Seguir → Flujo HTTP** (*Follow → HTTP Stream*).
4. Localizar la petición enviada por el cliente.
5. Tras las cabeceras HTTP hay una línea vacía: todo lo posterior a esa línea, hasta que termina la petición, es el **cuerpo** del POST.
6. Copiar únicamente ese cuerpo —sin `POST`, `Host`, `Cookie` ni la respuesta del servidor— a `nombre_diag.txt`.

Redacción breve para el examen: «Voy al paquete 12039, verifico el POST a `diag_Form`, sigo el flujo HTTP, separo cabeceras y cuerpo mediante la línea vacía y guardo exclusivamente el cuerpo de la petición en un fichero de texto».

## Bloque 3 — Filtros de captura BPF

Estos filtros se escriben **antes** de iniciar la captura. No llevan `==`, `ip.addr` ni `tcp.dstport`.

### 1. Tramas Ethernet cuyo origen es la pasarela predeterminada

```text
ether src <MAC_de_la_pasarela>
```

Primero se consulta la IP de la ruta por defecto y la MAC asociada en la tabla ARP/vecinos. Como se piden tramas Ethernet, se compara la **MAC**, no la IP.

### 2. Comunicaciones DNS con 10.0.4.254

```text
host 10.0.4.254 and port 53
```

Incluye DNS por UDP o TCP y en ambos sentidos.

### 3. ICMP Echo Reply intercambiados con 10.0.4.254

```text
icmp and host 10.0.4.254 and icmp[0] = 0
```

`icmp[0]` es el byte Type de ICMP; `0` identifica Echo Reply. Al capturar en la interfaz del propio equipo, `host 10.0.4.254` limita la conversación con esa máquina.

### 4. Datagramas IP con TTL menor de 64

```text
ip[8] < 64
```

El byte 8 de la cabecera IPv4 es el TTL.

### 5. TCP con SYN y ACK a 1

```text
tcp[13] & 0x12 = 18
```

El byte `tcp[13]` contiene los flags. La máscara hexadecimal `0x12` representa ACK (`0x10`) + SYN (`0x02`); su valor decimal es `18`. Este filtro requiere que ambos estén activos, aunque pueda haber otros flags activos.

## Recordatorio final

```text
Visualización: ip.src == 1.2.3.4 && tcp.dstport == 80
Captura BPF:   host 1.2.3.4 and port 80
```

No mezcles ambas sintaxis: es una de las trampas principales del modelo.
