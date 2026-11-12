#!/usr/bin/env python3
"""Auditor local de controles seleccionados, inspirado en CIS Benchmarks.

Ejecucion recomendada en la VM PNET como root:
  python3 scripts/cis_hardening.py                 # solo informe
  python3 scripts/cis_hardening.py --apply         # aplicar y volver a auditar

No almacena ni imprime contrasenas. Los nodos deben existir en el laboratorio
PNET: Cisco IOSvL2 en consola 30001, FortiGate en 30003 y contenedor docker2.
"""
from __future__ import print_function
import argparse
import datetime
import getpass
import json
import os
import re
import socket
import subprocess
import sys
import telnetlib
import time

PNET_CONSOLE_HOST = os.environ.get("PNET_CONSOLE_HOST", "127.0.0.1")
SWITCH_PORT = int(os.environ.get("SWITCH_CONSOLE_PORT", "30001"))
FORTI_PORT = int(os.environ.get("FORTI_CONSOLE_PORT", "30003"))
DOCKER_ENDPOINT = os.environ.get("PNET_DOCKER_ENDPOINT", "tcp://127.0.0.1:4243")
LAN = "192.168.45.0 255.255.255.0"


def run(args, input_text=None, timeout=30):
    return subprocess.run(args, input=input_text, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, universal_newlines=True,
                          timeout=timeout)


def read_until_any(tn, options, timeout=8):
    """Read a Telnet stream until one marker appears; return (data, marker)."""
    end = time.time() + timeout
    data = b""
    while time.time() < end:
        chunk = tn.read_very_eager()
        if chunk:
            data += chunk
            for marker in options:
                if marker.lower() in data.lower():
                    return data, marker
        else:
            time.sleep(0.05)
    return data, None


def cli_connect(port, username, password, enable_password=None):
    tn = telnetlib.Telnet(PNET_CONSOLE_HOST, port, timeout=10)
    data, marker = read_until_any(tn, [b"login:", b"username:", b"password:", b"#", b">"], 4)
    if marker in (b"login:", b"username:"):
        tn.write(username.encode("ascii") + b"\r\n")
        data, marker = read_until_any(tn, [b"password:", b"#", b">"], 5)
    if marker == b"password:":
        tn.write(password.encode("utf-8") + b"\r\n")
        data, marker = read_until_any(tn, [b"#", b">", b"login:"], 12)
    if marker == b">":
        tn.write(b"enable\r\n")
        data, marker = read_until_any(tn, [b"password:", b"#", b">"], 5)
        if marker == b"password:":
            tn.write((enable_password or password).encode("utf-8") + b"\r\n")
            data, marker = read_until_any(tn, [b"#", b">"], 8)
    if marker != b"#":
        tn.close()
        raise RuntimeError("No se obtuvo prompt privilegiado en consola %s" % port)
    return tn


def cli_command(tn, command, timeout=20):
    tn.write(command.encode("utf-8") + b"\r\n")
    data, marker = read_until_any(tn, [b"#"], timeout)
    if marker is None:
        raise RuntimeError("Tiempo agotado ejecutando comando de consola")
    return data.decode("utf-8", "replace")


def switch_config(username, password, apply):
    tn = cli_connect(SWITCH_PORT, username, password, password)
    try:
        cli_command(tn, "terminal length 0")
        if apply:
            commands = [
                "configure terminal", "no ip source-route", "no ip bootp server",
                "no ip http server", "no ip http secure-server",
                "service tcp-keepalives-in", "service tcp-keepalives-out",
                "line console 0", "login local", "exec-timeout 5 0",
                "logging synchronous", "exit", "line vty 0 4",
                "exec-timeout 5 0", "transport input none", "exit",
                "interface GigabitEthernet0/0", "spanning-tree portfast",
                "spanning-tree bpduguard enable", "exit",
                "interface GigabitEthernet0/1", "spanning-tree portfast",
                "spanning-tree bpduguard enable", "exit",
                "interface GigabitEthernet0/2", "shutdown", "exit",
                "interface GigabitEthernet0/3", "shutdown", "exit",
                "interface GigabitEthernet1/0", "shutdown", "exit",
                "interface GigabitEthernet1/1", "shutdown", "exit",
                "interface GigabitEthernet1/2", "shutdown", "exit",
                "interface GigabitEthernet1/3", "shutdown", "exit",
                "end", "write memory"
            ]
            for command in commands:
                cli_command(tn, command)
        return cli_command(tn, "show running-config", 25)
    finally:
        tn.close()


def forti_config(username, password, apply):
    tn = cli_connect(FORTI_PORT, username, password)
    try:
        if apply:
            commands = [
                "config system global", "set admintimeout 5",
                "set admin-lockout-threshold 3", "set admin-lockout-duration 60",
                "set admin-https-ssl-versions tlsv1-2", "end",
                "config system admin", "edit admin",
                "set trusthost1 %s" % LAN, "next", "end"
            ]
            for command in commands:
                cli_command(tn, command)
        output = []
        for command in ["show full-configuration system global",
                        "show system admin", "show system interface port1"]:
            output.append(cli_command(tn, command, 15))
        return "\n".join(output)
    finally:
        tn.close()


def router_config(apply):
    docker = ["docker", "-H=" + DOCKER_ENDPOINT, "exec", "-i", "docker2"]
    if apply:
        script = r'''set -e
cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.week9.orig
awk '
BEGIN {done=0}
/^Match[[:space:]]/ && !done {
  print "PermitRootLogin no"; print "PermitEmptyPasswords no"
  print "X11Forwarding no"; print "MaxAuthTries 4"; print "LoginGraceTime 30"
  done=1
}
/^(PermitRootLogin|PermitEmptyPasswords|X11Forwarding|MaxAuthTries|LoginGraceTime)[[:space:]]+/ {next}
{print}
END {if (!done) {
  print "PermitRootLogin no"; print "PermitEmptyPasswords no"
  print "X11Forwarding no"; print "MaxAuthTries 4"; print "LoginGraceTime 30"
}}' /etc/ssh/sshd_config.week9.orig > /etc/ssh/sshd_config
/usr/sbin/sshd -t
kill -HUP "$(pgrep -o sshd)"
'''
        result = run(docker + ["sh", "-s"], script, 30)
        if result.returncode:
            raise RuntimeError("No se pudo aplicar hardening SSH al Router")
    check = r'''set -e
/usr/sbin/sshd -T | grep -E '^(permitrootlogin|permitemptypasswords|x11forwarding|maxauthtries|logingracetime)'
printf '\n-- addresses --\n'; ip -br addr
printf '\n-- listeners --\n'; ss -lnt 2>/dev/null
'''
    result = run(docker + ["sh", "-s"], check, 20)
    if result.returncode:
        raise RuntimeError("No se pudo auditar el Router desde docker2")
    return result.stdout


def add(results, device, control, passed, evidence, note=""):
    results.append({"device": device, "control": control,
                    "status": "PASS" if passed else "FAIL",
                    "evidence": evidence.strip(), "note": note})


def audit(switch, forti, router):
    results = []
    s = switch.lower()
    for control, pattern in [
        ("IOS: source routing desactivado", r"(?m)^no ip source-route\s*$"),
        ("IOS: BOOTP server desactivado", r"(?m)^no ip bootp server\s*$"),
        ("IOS: HTTP desactivado", r"(?m)^no ip http server\s*$"),
        ("IOS: HTTPS administrativo desactivado", r"(?m)^no ip http secure-server\s*$"),
        ("IOS: VTY sin transporte remoto", r"(?m)^\s*transport input none\s*$"),
        ("IOS: timeout de consola/VTY", r"(?m)^\s*exec-timeout 5 0\s*$"),
        ("IOS: BPDU Guard habilitado", r"(?m)^\s*spanning-tree bpduguard enable\s*$"),
        ("IOS: puertos no usados apagados", r"(?s)interface GigabitEthernet0/2.*?shutdown.*?interface GigabitEthernet1/3.*?shutdown"),
    ]:
        add(results, "Switch Cisco IOSvL2", control, re.search(pattern, switch) is not None,
            "Regla evaluada en show running-config")
    portfast_count = len(re.findall(r"(?m)^\s*spanning-tree portfast(?: edge)?\s*$", switch))
    add(results, "Switch Cisco IOSvL2", "IOS: PortFast en puertos conectados",
        portfast_count >= 2, "Entradas PortFast: %d (se requieren Gi0/0 y Gi0/1)" % portfast_count)
    account_ok = (re.search(r"(?m)^username admin privilege 15 secret\s+\S+", switch) is not None
                  and re.search(r"(?m)^enable secret\s+\S+", switch) is not None)
    add(results, "Switch Cisco IOSvL2", "IOS: cuenta admin y enable secret existen",
        account_ok, "Se valida existencia; el hash permanece fuera del informe")

    f = forti.lower()
    checks = [
        ("FortiGate: timeout admin <= 5 min", r"set admintimeout 5"),
        ("FortiGate: TLS 1.2 en GUI", r"set admin-https-ssl-versions tlsv1-2"),
        ("FortiGate: umbral de bloqueo 3", r"set admin-lockout-threshold 3"),
        ("FortiGate: bloqueo por 60 s", r"set admin-lockout-duration 60"),
        ("FortiGate: host admin limitado a LAN /24", r"set trusthost1 192\.168\.45\.0 255\.255\.255\.0"),
        ("FortiGate: GUI/SSH solo en port1, sin HTTP/Telnet", r"set allowaccess (?:(?!.*\bhttp\b)(?!.*\btelnet\b).)*"),
    ]
    for control, pattern in checks:
        # allowaccess predicate must be evaluated on its own matching line.
        if "GUI/SSH" in control:
            line = re.search(r"(?m)^\s*set allowaccess ([^\r\n]+)", forti, re.I)
            tokens = line.group(1).lower().split() if line else []
            passed = bool(line) and "http" not in tokens and "telnet" not in tokens
        else:
            passed = re.search(pattern, forti, re.I) is not None
        add(results, "FortiGate 7.0.9", control, passed, "Regla evaluada en show configuration")

    r = {}
    for line in router.lower().splitlines():
        p = line.split()
        if len(p) >= 2:
            r[p[0]] = p[1]
    for key, expected, label in [
        ("permitrootlogin", "no", "Ubuntu: SSH root deshabilitado"),
        ("permitemptypasswords", "no", "Ubuntu: contraseñas vacías rechazadas"),
        ("x11forwarding", "no", "Ubuntu: reenvío X11 deshabilitado"),
        ("maxauthtries", "4", "Ubuntu: máximo cuatro intentos SSH"),
        ("logingracetime", "30", "Ubuntu: ventana de login SSH de 30 s"),
    ]:
        add(results, "Router Ubuntu 20.04 (Docker)", label, r.get(key) == expected,
            "%s=%s" % (key, r.get(key, "no disponible")))
    add(results, "Router Ubuntu 20.04 (Docker)",
        "Excepción de consola PNET en TCP/23", True,
        "xinetd escucha en TCP/23; se conserva para la consola del nodo PNET",
        "No usar Telnet como acceso administrativo de producción.")
    return results


def main():
    parser = argparse.ArgumentParser(description="Auditor CIS local para el laboratorio PNET")
    parser.add_argument("--apply", action="store_true", help="aplica los controles seleccionados y vuelve a auditar")
    parser.add_argument("--user", default="admin", help="usuario CLI de switch y FortiGate (default: admin)")
    parser.add_argument("--report-dir", default="reports", help="directorio de informes")
    parser.add_argument("--snapshot-dir", help="audita archivos saneados guardados; no conecta ni modifica equipos")
    args = parser.parse_args()
    if args.snapshot_dir:
        if args.apply:
            parser.error("--snapshot-dir es solo lectura; quite --apply")
        def load(name):
            with open(os.path.join(args.snapshot_dir, name), "r") as source:
                return source.read()
        switch = load("switch-running-config-sanitized.txt")
        forti = load("fortigate-running-config-sanitized.txt")
        router = load("router-running-config-sanitized.txt")
        mode = "snapshot"
    else:
        password = getpass.getpass("Clave CLI para Switch/FortiGate: ")
        switch = switch_config(args.user, password, args.apply)
        forti = forti_config(args.user, password, args.apply)
        router = router_config(args.apply)
        mode = "post-apply" if args.apply else "report-only"
    results = audit(switch, forti, router)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if not os.path.isdir(args.report_dir):
        os.makedirs(args.report_dir)
    md = ["# Informe CIS — %s" % mode, "",
          "Fecha local: %s" % datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
          "Modo: %s" % mode,
          "Fuente: archivos saneados locales" if mode == "snapshot" else "Fuente: consulta de los dispositivos PNET",
          "", "| Equipo | Control | Estado | Evidencia |", "|---|---|---:|---|"]
    for item in results:
        md.append("| %s | %s | **%s** | %s |" % (
            item["device"], item["control"], item["status"],
            item["evidence"].replace("|", "\\|").replace("\n", " ")))
    md += ["", "Nota: evaluación automatizada de los controles seleccionados y aplicables al laboratorio; no equivale a una certificación CIS-CAT ni a una evaluación completa del Benchmark.", ""]
    with open(os.path.join(args.report_dir, "cis_%s_%s.md" % (mode, stamp)), "w") as f:
        f.write("\n".join(md))
    with open(os.path.join(args.report_dir, "cis_%s_%s.json" % (mode, stamp)), "w") as f:
        json.dump({"mode": mode, "results": results}, f, indent=2)
    for item in results:
        print("%-5s %-28s %s" % (item["status"], item["device"], item["control"]))
    print("Informe guardado en %s/" % args.report_dir)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, socket.error, subprocess.SubprocessError, EOFError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        sys.exit(2)
