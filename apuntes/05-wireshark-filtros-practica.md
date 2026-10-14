# Wireshark - práctica de filtros, reglas y estadísticas

> **Regla de oro:** el filtro de **captura** usa sintaxis BPF y decide qué se guarda; el de **visualización** usa la sintaxis de Wireshark y solo oculta o muestra paquetes ya capturados. No se pueden intercambiar.

## Antes de empezar un boletín

1. Crea y activa un perfil propio (`Boletin_n1` o `Boletin_n2`).
2. Borra los filtros y reglas anteriores del perfil.
3. Sustituye los valores entre `<...>` por los de la práctica. Si el destino es un nombre web, resuélvelo primero a IP cuando el profesor lo pida.

## Filtros de visualización (Display filters)

Se aplican **después** de abrir o capturar tráfico, en la barra de filtros de Wireshark.

| Acción pedida | Filtro de visualización |
|---|---|
| Ethernet broadcast | `eth.dst == ff:ff:ff:ff:ff:ff` |
| Ethernet con MAC origen `<MAC>` | `eth.src == <MAC>` |
| Ethernet con MAC destino `<MAC>` | `eth.dst == <MAC>` |
| Todo el tráfico de una MAC | `eth.addr == <MAC>` |
| Tráfico entre dos MAC | `eth.addr == <MAC_1> && eth.addr == <MAC_2>` |
| Tráfico Ethernet donde **no** interviene una MAC | `!(eth.addr == <MAC>)` |
| ARP | `arp` |
| ARP Request | `arp.opcode == 1` |
| IP con origen `<IP>` | `ip.src == <IP>` |
| IP con destino `<IP>` | `ip.dst == <IP>` |
| Tráfico IP entre dos equipos | `ip.addr == <IP_1> && ip.addr == <IP_2>` |
| Todo el tráfico de una IP | `ip.addr == <IP>` |
| Tráfico IP donde no interviene una IP | `!(ip.addr == <IP>)` |
| ICMP | `icmp` |
| ICMP Echo Request | `icmp.type == 8` |
| ICMP Echo Reply | `icmp.type == 0` |
| ICMP Time Exceeded | `icmp.type == 11` |
| ICMP Echo Request/Reply entre dos IP | `(icmp.type == 8 || icmp.type == 0) && ip.addr == <IP_1> && ip.addr == <IP_2>` |
| TTL exactamente 1 | `ip.ttl == 1` |
| TTL menor o igual a 6 | `ip.ttl <= 6` |
| Respuestas DNS desde el puerto 53 | `udp.srcport == 53 || tcp.srcport == 53` |
| HTTP destinado a una IP concreta | `ip.dst == <IP> && tcp.dstport == 80` |
| Tramas que contienen un texto | `frame contains "<texto>"` |
| Peticiones HTTP que terminan en `.js` | `http.request.uri matches "\\.js$"` |
| FTP de control entre dos IP | `tcp.port == 21 && ip.addr == <IP_1> && ip.addr == <IP_2>` |
| FTP de datos entre dos IP | `tcp.port == 20 && ip.addr == <IP_1> && ip.addr == <IP_2>` |
| Paquetes enviados desde España (GeoIP activo) | `ip.geoip.country_iso == "ES"` |

### Respuestas directas del boletín 1

| Nombre del boletín | Filtro |
|---|---|
| Broadcast | `eth.dst == ff:ff:ff:ff:ff:ff` |
| Eth. origen PC1 | `eth.src == 00:11:d8:12:56:c4` |
| Eth. destino PC2 | `eth.dst == 00:30:da:ed:43:ad` |
| Eth. PC3 | `eth.addr == 01:00:5e:00:00:fb` |
| Eth. PC2 ↔ PC3 | `eth.addr == 00:11:d8:12:56:c4 && eth.addr == 01:00:5e:00:00:fb` |
| ARP | `arp` |
| ARP Request | `arp.opcode == 1` |
| Eth. NO PC1 | `!(eth.addr == 00:11:d8:12:56:c4)` |
| IP origen 50.57.203.250 | `ip.src == 50.57.203.250` |
| IP destino 192.16.192.166 | `ip.dst == 192.16.192.166` |
| IP_101 ↔ IP_80.58.32.97 | `ip.addr == 192.168.0.101 && ip.addr == 80.58.32.97` |
| IP_80.58.32.97 | `ip.addr == 80.58.32.97` |
| NO IP_80.58.32.97 | `!(ip.addr == 80.58.32.97)` |
| ICMP | `icmp` |
| ICMP Echo Request | `icmp.type == 8` |
| ICMP Tiempo Excedido | `icmp.type == 11` |
| TTL 1 | `ip.ttl == 1` |
| TTL 6 | `ip.ttl <= 6` |
| ICMP IP_74 ↔ IP_1 | `(icmp.type == 8 || icmp.type == 0) && ip.addr == 74.125.230.210 && ip.addr == 192.168.0.1` |
| DNS | `udp.srcport == 53 || tcp.srcport == 53` |
| www.atareao.es | `ip.dst == 92.43.17.150 && tcp.dstport == 80` |
| Atareao.es | `frame contains "atareao.es"` |
| Atareao.es_js | `http.request.uri matches "\\.js$"` |
| FTP-Control | `tcp.port == 21 && ip.addr == 192.168.0.1 && ip.addr == 130.206.1.5` |
| FTP-Data | `tcp.port == 20 && ip.addr == 192.168.0.1 && ip.addr == 130.206.1.5` |

## Reglas de coloreado

Ruta: **View → Coloring Rules**. La regla que aparece antes tiene prioridad si varias coinciden.

| Regla | Filtro |
|---|---|
| ARP | `arp` |
| Errores ICMP: destino inalcanzable, source quench, redirect o tiempo excedido | `icmp.type == 3 || icmp.type == 4 || icmp.type == 5 || icmp.type == 11` |
| ICMP | `icmp` |
| TTL inferior a 10 | `ip.ttl < 10` |

## Estadísticas y gráfico del boletín 1

| Lo que preguntan | Dónde verlo |
|---|---|
| Equipos, paquetes enviados/recibidos y bytes por MAC o IP | **Statistics → Endpoints**; pestañas Ethernet e IPv4 |
| Conversación más activa por Ethernet, IP, TCP o UDP | **Statistics → Conversations**; pestaña correspondiente; ordenar por Bytes o Packets |
| Protocolos presentes | **Statistics → Protocol Hierarchy** |
| Evolución temporal de HTTP, FTP y DNS | **Statistics → I/O Graphs**; crear tres líneas con filtros `http`, `ftp` y `dns` |

Para el dibujo TCP/IP, toma los protocolos de **Protocol Hierarchy** y sitúalos por capa: enlace (Ethernet/ARP), Internet (IP/ICMP), transporte (TCP/UDP) y aplicación (DNS, HTTP, FTP, etc.).

## Filtros de captura (Capture filters, BPF)

Se escriben **antes** de iniciar la captura. Sintaxis distinta: usa `host`, `src host`, `dst host`, `port`, `net`, `and`, `or`, `not`; no admite expresiones como `ip.addr` ni `tcp.flags.syn`.

| Acción pedida | Filtro de captura |
|---|---|
| Todo el tráfico IP de mi equipo | `ip and host <MI_IP>` |
| IP enviado por mi equipo | `ip and src host <MI_IP>` |
| IP destinado a mi equipo | `ip and dst host <MI_IP>` |
| Tráfico IP de un servidor web | `ip and host <IP_O_NOMBRE>` |
| Todo excepto una IP/equipo | `not host <IP_O_NOMBRE>` |
| Todo el tráfico de una MAC | `ether host <MAC>` |
| Ethernet con MAC origen | `ether src <MAC>` |
| Ethernet con MAC destino | `ether dst <MAC>` |
| Tráfico entre dos MAC | `ether host <MAC_1> and ether host <MAC_2>` |
| Ethernet broadcast | `ether broadcast` |
| ARP / no ARP | `arp` / `not arp` |
| ICMP | `icmp` |
| Cualquier origen o destino puerto 80 | `port 80` |
| Destino puerto 80 | `dst port 80` |
| Origen puerto 53 | `src port 53` |
| Todo excepto TCP puerto 80 | `not tcp port 80` |
| UDP puerto 53 | `udp port 53` |
| TCP / UDP | `tcp` / `udp` |
| Tráfico de la red local | `net <RED_LOCAL>/<PREFIJO>` |
| Origen en red privada 192.168.0.0/16 | `src net 192.168.0.0/16` |
| HTTP de un sitio | `host <IP_O_NOMBRE> and tcp port 80` |
| HTTPS de un sitio | `host <IP_O_NOMBRE> and tcp port 443` |
| TTL menor de 128 | `ip[8] < 128` |
| ICMP Echo Request | `icmp[0] == 8` |
| ICMP Time Exceeded | `icmp[0] == 11` |
| ICMP Echo Request o Reply | `icmp[0] == 8 or icmp[0] == 0` |
| Ping entre dos hosts | `icmp and host <HOST_1> and host <HOST_2>` |
| UDP con puerto origen bien conocido | `udp src portrange 0-1023` |
| TCP solo SYN (ningún otro flag activo) | `tcp[13] == 2` |
| TCP con SYN activo, aunque tenga más flags | `tcp[13] & 2 != 0` |
| Paquetes IPv4 con DF activado | `ip[6:2] & 0x4000 != 0` |

### Respuestas directas del boletín 2

| Nombre del boletín | Filtro |
|---|---|
| Mi equipo | `ip and host <MI_IP>` |
| Desde mi equipo | `ip and src host <MI_IP>` |
| Para mi equipo | `ip and dst host <MI_IP>` |
| CiudadWireless | `ip and host www.ciudadwireless.com` |
| NO www.xunta.es | `not host www.xunta.es` |
| Eth. server01 | `ether host <MAC_SERVER01>` |
| Eth. origen server01 | `ether src <MAC_SERVER01>` |
| Eth. destino server01 | `ether dst <MAC_SERVER01>` |
| Eth. PC3 | `ether host 00:00:00:00:00:01` |
| Eth. Mio ↔ Router | `ether host <MI_MAC> and ether host <MAC_GATEWAY>` |
| Broadcast | `ether broadcast` |
| ARP / NO ARP | `arp` / `not arp` |
| ICMP | `icmp` |
| Puerto 80 / destino puerto 80 | `port 80` / `dst port 80` |
| Origen puerto 53 | `src port 53` |
| NO TCP 80 | `not tcp port 80` |
| UDP 53 | `udp port 53` |
| TCP / UDP | `tcp` / `udp` |
| Red local | `net <RED_LOCAL>/<PREFIJO>` |
| Red Priv Clase C | `src net 192.168.0.0/16` |
| Web www.edu.xunta.es | `host www.edu.xunta.es and tcp port 80` |
| https www.edu.xunta.es | `host www.edu.xunta.es and tcp port 443` |
| TTL < 128 | `ip[8] < 128` |
| ICMP Echo Request | `icmp[0] == 8` |
| ICMP Tiempo Excedido | `icmp[0] == 11` |
| ICMP Echo | `icmp[0] == 8 or icmp[0] == 0` |
| Ping Yo ↔ server01 | `icmp and host <MI_IP> and host <IP_SERVER01>` |
| UDP Bien Conocidos | `udp src portrange 0-1023` |
| TCP solo SYN | `tcp[13] == 2` |
| TCP SYN | `tcp[13] & 2 != 0` |
| NO Fragmentación (DF) | `ip[6:2] & 0x4000 != 0` |

## Errores que no debes cometer

- `ip.addr == ...` es de **visualización**; en captura usa `host ...`.
- Para "no intervenga" no uses `eth.addr != <MAC>` ni `ip.addr != <IP>`: una trama puede tener una dirección distinta en un extremo y aun así involucrar a la dirección que quieres excluir. Usa `!(...)`.
- `tcp[13] == 2` significa **solo SYN**; `tcp[13] & 2 != 0` significa que SYN está activo, por ejemplo también en SYN+ACK.
- Un filtro de captura no recupera lo que no se guardó. Si dudas, captura más y acota luego con un display filter.
