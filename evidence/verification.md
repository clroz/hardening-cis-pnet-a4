# Registro de comprobaciones

Fecha de trabajo: 12 de noviembre de 2026 (zona horaria de la VM PNET: UTC).

| Elemento | Observación de consola | Resultado |
|---|---|---|
| Router IP | `eth1 192.168.45.1/24` | Confirmado |
| Router contraseña | `passwd -S root` → `root P` | Clave establecida; no se revela su valor |
| Router SSH | `sshd -t`; `sshd -T` | `permitrootlogin no`, `permitemptypasswords no`, `x11forwarding no`, `maxauthtries 4`, `logingracetime 30` |
| Switch SVI | VLAN1 `192.168.45.2/24` | Confirmado |
| Switch hardening | Running-config | BOOTP y HTTP(S) deshabilitados, source-route deshabilitado, BPDU Guard, puertos no usados apagados, timeout 5 min, VTY sin transporte |
| Switch acceso | Login `admin` y prompt privilegiado | Confirmado por consola |
| FortiGate | FortiOS 7.0.9, port1 `192.168.45.3/24` | Confirmado |
| FortiGate administración | Trusted host `.45.0/24`, TLS1.2, timeout 5, lockout 3/60, allowaccess ping/https/ssh | Confirmado mediante CLI |
| FortiGate conectividad | ICMP a `192.168.45.1` | Respuestas recibidas |
| Verificador (snapshot saneado) | `python3 scripts/cis_hardening.py --snapshot-dir configs` | 22 PASS, 0 FAIL en los tres archivos saneados; informe en `reports/cis_snapshot_20261112_161603.md` |
| Pruebas del analizador | `python3 -m unittest -v` | 3 pruebas aprobadas: valores esperados, detección de valor SSH inseguro y detección de HTTP administrativo |

El informe snapshot es de solo lectura y analiza archivos saneados. Ejecutar además los modos `report-only` y `--apply` contra los nodos encendidos desde PNET para generar sus informes en vivo.
