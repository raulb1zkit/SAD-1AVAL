# UD01 - Fundamentos, seguridad y alta disponibilidad

## Principios y riesgo

| Pilar | Significado | Controles habituales |
|---|---|---|
| Fiabilidad | el sistema funciona como fue diseñado | pruebas, mantenimiento, redundancia |
| Confidencialidad | solo acceden autorizados | cifrado, ACL, mínimo privilegio |
| Integridad | no hay cambios no autorizados | hashes, firma, control de cambios |
| Disponibilidad | recursos accesibles cuando se requieren | SAI, redundancia, plan de contingencia |
| Autenticación | se verifica identidad | MFA, certificados, contraseña |
| No repudio | se puede probar autoría/recepción | firma digital, evidencias |

```text
Activo + vulnerabilidad + amenaza
              -> ataque materializado -> impacto

Riesgo = posibilidad de que la amenaza aproveche la vulnerabilidad.
```

- **Activo**: datos, software, hardware, red, soporte, instalación, personal o servicio.
- **Amenaza**: circunstancia capaz de dañar.
- **Vulnerabilidad**: debilidad aprovechable.
- **Ataque**: materialización de la amenaza.
- **Impacto**: daño que produce.

## Análisis de vulnerabilidades

```text
Inventariar activos -> controles existentes -> vulnerabilidades -> amenazas/daño
-> objetivos -> priorizar y aplicar medidas -> revisión periódica
```

OpenVAS/Greenbone y Nessus revisan sistemas, servicios, puertos, parches y configuraciones. CONAN Mobile analiza seguridad de Android. Un hallazgo necesita contexto: exposición, impacto y corrección disponible.

## Amenazas

| Ataque sobre información | Tipo | Pilar afectado | Ejemplo |
|---|---|---|---|
| Interceptación | pasivo | confidencialidad | escucha de tráfico |
| Interrupción | activo | disponibilidad | DoS |
| Modificación | activo | integridad | alterar tráfico |
| Fabricación | activo | autenticación | phishing/mensaje falso |

| Amenaza física | Daño | Prevención |
|---|---|---|
| temperatura, polvo, aire inadecuado | avería/vida útil menor | climatización, filtrado |
| agua | daños en cableado/equipos | ubicación, detección |
| incendio | pérdida de bienes/datos | detección/extinción |
| acceso físico/error humano | robo, sabotaje, borrado | control de acceso, procedimientos |
| corte eléctrico | parada/daño | SAI y generador |

### Malware

| Tipo | Idea |
|---|---|
| Bug | error de software; se corrige con parche |
| Troyano | aparenta ser legítimo y ejecuta acciones ocultas |
| Backdoor | acceso remoto oculto/persistente |
| Bomba lógica | se activa bajo condición |
| Virus | código asociado a fichero/ejecución |
| Gusano | se replica solo y consume red/recursos |
| Spyware/stealer | espía o roba datos y credenciales |
| Adware | publicidad y posible seguimiento |
| Ransomware | cifra/bloquea y exige rescate |
| Botnet | equipos infectados controlados en grupo |

Análisis seguro: **sandbox** aislada. Estático = estudiar fichero sin ejecutarlo; dinámico = observar su conducta controlada.

## Seguridad física y contingencia

```text
Red CA -> rectificador -> batería (CC) -> inversor -> equipos (CA)
```

| Solución | Idea |
|---|---|
| SAI offline | entra al fallar red; protección más limitada |
| SAI line-interactive | corrige fluctuaciones; transición de milisegundos |
| SAI online | aísla/regenera salida; mayor protección |
| Grupo electrógeno | da autonomía prolongada; complementa, no reemplaza, el SAI |

Antes de planificar: **qué proteger, qué puede fallar, frecuencia y consecuencias**.

```text
Antes: respaldo (copias, recursos, procedimientos)
Durante: emergencia (contener y minimizar daño)
Después: recuperación (restaurar y documentar)
```

## Seguridad lógica

| Aspecto | Simétrico | Asimétrico |
|---|---|---|
| Claves | una clave secreta compartida | pública + privada |
| Ventaja | rápido para mucho volumen | distribución de clave y firma |
| Limitación | intercambio/gestión de claves | más costoso |
| Uso | cifrar datos/sesión | intercambio, autenticación, firma |

La pública se comparte; la privada no. Para confidencialidad hacia A se usa la clave pública de A; A descifra con la privada. La **firma digital** aporta autenticidad, integridad y evidencia de autoría, no confidencialidad.

- **ACL**: reglas de acceso y privilegios para recursos o tráfico.
- Contraseñas: largas, únicas y no predecibles; riesgos: fuerza bruta, diccionario, phishing y keylogger. Complementar con MFA.
- Biometría: alta = crear *template*; verificación = comparar muestra con template. No es infalible.

## RAID, copias y recuperación

`N` es el número de discos iguales. RAID aumenta rendimiento y/o tolerancia, pero **no es backup**.

| Nivel | Organización | Mín. | Fallos soportados | Capacidad útil | Lectura/escritura | Ventaja | Limitación |
|---|---|---:|---|---:|---|---|---|
| RAID 0 | striping, datos repartidos | 2 | 0 | N | muy rápidas | rendimiento/capacidad | un disco perdido = todo perdido |
| RAID 1 | espejo | 2 | 1 por espejo | aprox. N/2 | lectura buena; escritura duplicada | sencillo y redundante | 50% de capacidad con pares |
| RAID 5 | datos + paridad distribuida | 3 | 1 | N - 1 | lectura buena; escritura penalizada | equilibrio | dos fallos = pérdida |
| RAID 6 | doble paridad distribuida | 4 | 2 | N - 2 | escritura más penalizada | alta tolerancia | coste de dos discos |
| RAID 0+1 | espejo de RAID 0 | 4 | depende del conjunto | aprox. N/2 | alto rendimiento | striping + espejo | menos robusto que 10 |
| RAID 10 (1+0) | striping sobre espejos | 4 | varios, si no cae un espejo entero | aprox. N/2 | muy buena | BBDD/alta E/S | coste de capacidad |

```text
Solo rendimiento/datos prescindibles -> RAID 0
Redundancia sencilla                 -> RAID 1
Equilibrio capacidad/protección      -> RAID 5
Tolerar dos discos                   -> RAID 6
Rendimiento alto + redundancia       -> RAID 10
```

Una **copia** recupera datos; una **imagen** restaura un estado completo. Recuperación **lógica**: ficheros/particiones; **física**: soporte dañado. El borrado seguro busca impedir recuperación; Gutmann es una técnica histórica de sobrescritura.

## Auditoría y análisis forense

Auditoría completa = visión global; parcial = ámbito concreto. Forense:

```text
preservar evidencia -> trabajar sobre copias -> autenticar/proteger
-> analizar -> documentar -> informe
```

Legalidad, integridad, cadena de custodia y reproducibilidad son esenciales. Evidencias: ficheros, logs, memoria, tráfico, metadatos y dispositivos.
