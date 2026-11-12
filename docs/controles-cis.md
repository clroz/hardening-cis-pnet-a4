# Propósito, alcance y controles aplicados

## Propósito del laboratorio

Endurecer y comprobar la administración de la red existente en PNET. El laboratorio busca reducir la exposición de administración, endurecer el acceso por consola/SSH y limitar errores de capa 2. El direccionamiento usa `192.168.45.0/24`, derivado de la matrícula 20221745. Se mantuvieron los equipos ya provistos: FortiGate, Cisco IOSvL2 y Router Ubuntu en contenedor.

## Referencias CIS

- [CIS Fortinet Benchmarks](https://www.cisecurity.org/benchmark/fortinet) — referencia del FortiGate 7.0.x Benchmark v1.4.0.
- [CIS Cisco IOS Benchmark v2.2 (PDF oficial archivado)](https://www.cisecurity.org/-/jssmedia/Project/cisecurity/cisecurity/data/media/files/uploads/2017/04/CIS_Cisco_IOS_Benchmark_v22.pdf) — referencia histórica compatible con el IOSvL2 15.2 del switch. La [página actual de CIS Cisco](https://www.cisecurity.org/benchmark/cisco) enumera las ediciones vigentes.
- [CIS Ubuntu Linux Benchmarks](https://www.cisecurity.org/benchmark/ubuntu_linux) — incluye Ubuntu Linux 20.04 LTS Benchmark v3.0.0, aplicable a la base del Router.
- [Referencia oficial FortiOS 7.0.9: `config system global`](https://docs.fortinet.com/document/fortigate/7.0.9/cli-reference/1620) — versiones TLS disponibles para el HTTPS administrativo.

El script comprueba una selección documentada de controles aplicables, no todos los puntos de los Benchmarks. Se evita atribuir números de recomendación que dependen de la edición exacta del PDF.

## Matriz de controles

| Equipo | Recomendación aplicada | Motivo | Comprobación |
|---|---|---|---|
| FortiGate | Usuario `admin` limitado por trusted host a `192.168.45.0/24` | Restringe el origen de administración al segmento del laboratorio | `show system admin` |
| FortiGate | Timeout administrativo de 5 minutos y bloqueo tras 3 intentos durante 60 segundos | Reduce sesiones desatendidas y fuerza bruta | `show full-configuration system global` |
| FortiGate | HTTPS administrativo con TLS 1.2 | Evita protocolos TLS antiguos; el CLI de FortiOS 7.0.9 documenta TLS 1.2 y 1.3 | `show full-configuration system global` |
| FortiGate | En `port1`, administración HTTPS/SSH; sin HTTP ni Telnet | Evita administración web en claro y Telnet | `show system interface port1` |
| Cisco IOSvL2 | `no ip source-route`, `no ip bootp server`, HTTP/HTTPS desactivados | Reduce servicios y funciones no requeridos para este switch | `show running-config` |
| Cisco IOSvL2 | BPDU Guard y PortFast en Gi0/0–Gi0/1; puertos no usados apagados | Protege los puertos de acceso y reduce conexiones físicas innecesarias | `show running-config` y `show spanning-tree` |
| Cisco IOSvL2 | Timeout de 5 minutos; acceso VTY remoto deshabilitado | Reduce sesiones administrativas expuestas; se conserva la consola PNET | `show running-config` |
| Router Ubuntu | SSH root deshabilitado; contraseñas vacías denegadas; X11 desactivado; 4 intentos y 30 s de login | Reduce opciones de abuso del servicio SSH | `sshd -t` y `sshd -T` |

La contraseña pedida para las cuentas administrativas se configura en los nodos, no se documenta ni se incluye en el script. Las configuraciones adjuntas eliminan hashes y secretos.

## Pruebas realizadas

- El Router conserva `eth1 192.168.45.1/24`; `passwd -S root` confirmó una clave establecida sin exponer su hash.
- El FortiGate tiene `port1 192.168.45.3/24`, TLS 1.2, timeout 5, lockout 3/60 y trusted host `192.168.45.0/24`.
- El FortiGate alcanzó `192.168.45.1` por ICMP.
- En el switch se confirmó `192.168.45.2/24`, ausencia de BOOTP/web, `no ip source-route`, BPDU Guard, VTY sin transporte y apagado de puertos sin uso. La clave local fue probada por consola y la configuración se guardó.
- Tras el hardening del Router, `sshd -t` terminó correctamente. `sshd -T` devolvió `permitrootlogin no`, `permitemptypasswords no`, `x11forwarding no`, `maxauthtries 4`, `logingracetime 30`.

## Excepción de consola

El contenedor Router conserva un listener TCP/23 de `xinetd` utilizado por la consola del nodo PNET. Se mantiene para no perder el acceso de laboratorio. No se recomienda Telnet para administración de producción; el informe lo marca como excepción documentada y no como control aprobado.

