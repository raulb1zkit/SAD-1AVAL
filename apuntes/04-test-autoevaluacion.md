# Test tipo test - Seguridad y Alta Disponibilidad

Una única respuesta correcta. Corrige solo al terminar.

1. Una debilidad que puede aprovechar una amenaza es:
   - A. Impacto
   - B. Vulnerabilidad
   - C. Activo
   - D. Riesgo

2. Escuchar tráfico sin alterarlo compromete principalmente:
   - A. Disponibilidad
   - B. Fiabilidad
   - C. Confidencialidad
   - D. No repudio

3. La cadena correcta es:
   - A. Ataque -> vulnerabilidad -> amenaza -> impacto
   - B. Amenaza aprovecha vulnerabilidad -> ataque -> impacto
   - C. Impacto -> activo -> amenaza -> ataque
   - D. Riesgo -> impacto -> vulnerabilidad -> activo

4. ¿Qué RAID no tolera el fallo de ningún disco?
   - A. RAID 0
   - B. RAID 1
   - C. RAID 5
   - D. RAID 6

5. Con N discos, RAID 6 ofrece capacidad útil:
   - A. N
   - B. N - 1
   - C. N - 2
   - D. N / 2 siempre

6. Para BBDD con alta E/S y redundancia elegirías:
   - A. RAID 0
   - B. RAID 5
   - C. RAID 10
   - D. JBOD

7. La afirmación correcta sobre RAID es:
   - A. RAID 1 elimina la necesidad de backups.
   - B. RAID sustituye un plan de recuperación.
   - C. Puede dar tolerancia, pero no sustituye una copia.
   - D. RAID 0 usa paridad distribuida.

8. La fase del plan de contingencia que se ejecuta durante el incidente es:
   - A. Respaldo
   - B. Emergencia
   - C. Recuperación
   - D. Auditoría

9. El cifrado simétrico:
   - A. Usa una clave pública y una privada.
   - B. Usa una misma clave secreta para cifrar y descifrar.
   - C. No usa claves.
   - D. Solo sirve para firma.

10. Una firma digital aporta:
    - A. Confidencialidad por sí sola.
    - B. Integridad, autenticidad y evidencia de autoría.
    - C. Disponibilidad.
    - D. Ocultación del origen.

11. Falsear asociaciones IP-MAC para interponerse es:
    - A. DNS spoofing
    - B. ARP spoofing
    - C. DHCP starvation
    - D. MAC filtering

12. ¿Qué control ayuda contra MAC flooding?
    - A. Port Security
    - B. DNSSEC
    - C. DMARC
    - D. CSP

13. SPF, DKIM y DMARC se emplean principalmente para:
    - A. Cifrar discos.
    - B. Autenticidad/integridad de correo.
    - C. Proteger Wi-Fi.
    - D. Analizar malware.

14. La defensa principal contra SQL injection es:
    - A. Ocultar SSID.
    - B. Consultas parametrizadas.
    - C. Filtrar MAC.
    - D. Usar SAI.

15. En XSS almacenado, el contenido malicioso:
    - A. Solo existe en una URL.
    - B. Se guarda y puede afectar a visitantes posteriores.
    - C. Modifica una tabla ARP.
    - D. Agota direcciones DHCP.

16. Un *salt* sirve para:
    - A. Cifrar tráfico.
    - B. Evitar hashes iguales con contraseñas iguales.
    - C. Reemplazar la contraseña.
    - D. Firmar certificados.

17. ¿Cuál es MFA real?
    - A. Dos contraseñas.
    - B. Contraseña y pregunta secreta.
    - C. PIN y contraseña.
    - D. Contraseña y código de app autenticadora.

18. Sobre Wi-Fi, es correcto que:
    - A. WEP es recomendado actualmente.
    - B. SSID oculto es autenticación fuerte.
    - C. WPA3 es preferible; WPA2-AES sirve por compatibilidad.
    - D. Filtrar MAC impide toda suplantación.

19. En WPA-Enterprise, las credenciales las suele validar:
    - A. El supplicant.
    - B. El AP por sí solo.
    - C. RADIUS.
    - D. El portal cautivo.

20. La diferencia fundamental del IPS frente a IDS es que:
    - A. IPS solo registra e IDS bloquea.
    - B. IPS puede bloquear o descartar tráfico.
    - C. IDS solo funciona en Wi-Fi.
    - D. No existe diferencia.

## Plantilla

```text
 1.___  2.___  3.___  4.___  5.___
 6.___  7.___  8.___  9.___ 10.___
11.___ 12.___ 13.___ 14.___ 15.___
16.___ 17.___ 18.___ 19.___ 20.___
```

## Soluciones

| Nº | Resp. | Idea |
|---:|:---:|---|
| 1 | B | Debilidad aprovechable. |
| 2 | C | Interceptación pasiva = confidencialidad. |
| 3 | B | Ataque materializa amenaza que aprovecha debilidad. |
| 4 | A | RAID 0 no tiene redundancia. |
| 5 | C | RAID 6 reserva dos discos equivalentes. |
| 6 | C | RAID 10: espejos + rendimiento. |
| 7 | C | RAID no protege de borrado/corrupción/desastre. |
| 8 | B | Emergencia ocurre durante. |
| 9 | B | Secreto compartido. |
| 10 | B | Firma no cifra por sí sola. |
| 11 | B | ARP une IP con MAC. |
| 12 | A | Limita MAC por puerto. |
| 13 | B | Seguridad y política de correo. |
| 14 | B | Separa datos del código SQL. |
| 15 | B | Persiste para otros usuarios. |
| 16 | B | Reduce hashes repetidos/rainbow tables. |
| 17 | D | Factor saber + factor tener. |
| 18 | C | WEP/WPA-TKIP obsoletos. |
| 19 | C | Validación centralizada. |
| 20 | B | IPS detecta y previene. |
