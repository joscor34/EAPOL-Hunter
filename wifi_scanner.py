#!/usr/bin/env python3
"""
WiFi Scanner + Handshake Extractor — Modo Monitor

Escanea redes WiFi, captura handshakes WPA/WPA2 (EAPOL 4-way y PMKID)
y los guarda en formato hc22000 compatible con hashcat (-m 22000).

Uso:
    sudo python3 wifi_scanner.py -i wlan0
    sudo python3 wifi_scanner.py -i wlan0 -o capturas/ --deauth

ADVERTENCIA: --deauth envía frames de desautenticación. Úsalo únicamente
en redes propias o sobre las que tengas autorización explícita por escrito.

Estructura del paquete scanner/:
    models.py    — NetworkInfo, HandshakeData (dataclasses)
    interface.py — InterfaceManager  (modo monitor, channel hopping)
    parser.py    — PacketParser      (Beacon, EAPOL Key)
    saver.py     — HandshakeSaver    (escribe .hc22000 y .pcap)
    display.py   — TerminalDisplay   (tabla TUI + log de eventos)
    capture.py   — HandshakeCapture  (orquesta la captura)
    main.py      — main()            (args, señales, hilos, sniff)
"""

from scanner import main




if __name__ == "__main__":
    main()
