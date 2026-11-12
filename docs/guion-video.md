# Guion sugerido para el video (máximo 10 minutos)

Graba la demostración personalmente, con rostro y voz visibles/audibles y fecha/hora del sistema en pantalla. No reutilices el video de otra asignación.

1. **0:00–0:40** — Presentar nombre, matrícula, fecha/hora y propósito: aplicar controles CIS en la topología existente.
2. **0:40–1:30** — Mostrar topología PNET e identificar FortiGate, switch y Router; señalar la red `192.168.45.0/24`.
3. **1:30–3:10** — En el switch, mostrar `show ip interface brief` y las líneas CIS de `show running-config` (sin mostrar hashes/secretos).
4. **3:10–4:40** — En FortiGate, mostrar el IP de `port1`, trusted host, timeout, TLS y lockout. No revelar la contraseña.
5. **4:40–5:40** — En Router, mostrar `sshd -T` con las cinco opciones endurecidas y `sshd -t` exitoso.
6. **5:40–7:30** — Ejecutar primero el script sin `--apply`, abrir el informe; luego ejecutar `--apply` y mostrar el informe posterior.
7. **7:30–8:20** — Probar conectividad de los equipos de la LAN y concluir cómo los controles reducen exposición.

Antes de publicar, confirma que el video dura menos de diez minutos, que rostro/voz/fecha/hora se distinguen y que no aparecen claves o hashes.

