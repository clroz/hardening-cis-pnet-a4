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
| FortiGate running-config | Exportado con `show full-configuration`; valores sensibles saneados | `configs/fortigate-running-config-sanitized.txt` |
| FortiGate conectividad | ICMP a `192.168.45.1` | Respuestas recibidas |
| Verificador (solo lectura en vivo) | `python3 scripts/cis_hardening.py` | 22 PASS, 0 FAIL; `reports/cis_report-only_20261112_183615.md` |
| Verificador (aplicar y revisar) | `python3 scripts/cis_hardening.py --apply` | 22 PASS, 0 FAIL después de aplicar; `reports/cis_post-apply_20261112_183654.md` |
| Verificador snapshot | `python3 scripts/cis_hardening.py --snapshot-dir configs` | 22 PASS, 0 FAIL con running-configs completos saneados; `reports/cis_snapshot_20261112_184511.md` |
| Pruebas del analizador | `python3 -m unittest -v` | 3 pruebas aprobadas: valores esperados, detección de valor SSH inseguro y detección de HTTP administrativo |

Los informes incluyen fecha y hora UTC de PNET. Configuraciones y reportes se publicaron sin la contraseña ni hashes.
