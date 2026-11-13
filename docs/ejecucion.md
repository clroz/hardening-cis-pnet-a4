# Uso del escáner y remediador

## Requisitos y contexto

- Ejecutar dentro de la VM PNET, como `root`; el script usa las consolas locales TCP 30001 y 30003 y el endpoint Docker local `tcp://127.0.0.1:4243`.
- Python 3.6 o posterior y los nodos existentes encendidos.
- La cuenta `admin` del switch y FortiGate debe tener permiso de configuración. La contraseña se solicita con entrada oculta y no se escribe a disco.
- Para una ejecución no interactiva, el operador puede definir `CIS_CLI_PASSWORD` únicamente en el entorno del proceso y eliminarla al terminar. No debe guardarse en el repositorio ni en archivos de inicio del shell.

## Modo informe

```bash
python3 scripts/cis_hardening.py
```

Solo lee configuración y genera `reports/cis_report-only_<fecha>.md` y `.json`. No envía comandos de configuración.

## Aplicar y generar informe posterior

```bash
python3 scripts/cis_hardening.py -a
```

El modo `-a` (equivalente a `--apply`) aplica los controles definidos en el script a switch, FortiGate y SSH del Router, vuelve a consultar los valores efectivos y genera `cis_post-apply_<fecha>.md` y `.json`. La remediación es idempotente para las reglas incluidas. Conserva una copia local del `sshd_config` original en el contenedor Router como `/etc/ssh/sshd_config.week9.orig`.

## Analizar archivos saneados

```bash
python3 scripts/cis_hardening.py --snapshot-dir configs
```

Este modo de solo lectura sirve para revisar los extractos compartidos y probar el analizador sin abrir sesiones a los equipos. No sustituye la auditoría en vivo.

También se pueden cambiar las direcciones de consola mediante variables de entorno `PNET_CONSOLE_HOST`, `SWITCH_CONSOLE_PORT`, `FORTI_CONSOLE_PORT` y `PNET_DOCKER_ENDPOINT`.

## Lectura del resultado

`PASS` significa que la regla comprobada coincide con el valor esperado. `FAIL` indica que el control está ausente o no coincide. El listener TCP/23 del contenedor se registra como excepción de consola PNET. Un `PASS` de este script no reemplaza CIS-CAT ni el análisis de todos los controles de un Benchmark.

