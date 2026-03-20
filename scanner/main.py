"""
Punto de entrada de la aplicación: parsea argumentos, arranca hilos y sniff.
"""

import argparse
import os
import signal
import sys
import threading
from pathlib import Path

from scapy.all import sniff

from .capture import HandshakeCapture
from .display import TerminalDisplay
from .interface import InterfaceManager
from .saver import HandshakeSaver


def _check_root() -> None:
    if os.geteuid() != 0:
        print("[-] Requiere root: sudo python3 wifi_scanner.py -i wlan0")
        sys.exit(1)


def _build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description="Escanea redes WiFi y captura handshakes WPA/WPA2 en formato hc22000.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  sudo python3 wifi_scanner.py -i wlan0\n"
            "  sudo python3 wifi_scanner.py -i wlan0 -o /tmp/capturas --deauth\n\n"
            "hashcat (tras capturar):\n"
            "  hashcat -m 22000 capturas/MiRed_*.hc22000 wordlist.txt\n\n"
            "AVISO: --deauth solo debe usarse en redes propias o con autorización explícita."
        ),
    )


def main() -> None:
    parser = _build_parser()
    parser.add_argument("-i", "--interface", required=True, metavar="IFACE",
                        help="Interfaz WiFi (ej: wlan0)")
    parser.add_argument("-o", "--output", default="capturas", metavar="DIR",
                        help="Directorio de salida para .hc22000 y .pcap (def: capturas/)")
    parser.add_argument("--deauth", action="store_true",
                        help="Enviar frames deauth para forzar reconexión (solo redes autorizadas)")
    parser.add_argument("--no-hop", dest="hop", action="store_false", default=True,
                        help="Desactiva el salto de canal (fija el canal actual)")

    args = parser.parse_args()
    _check_root()

    output_dir = Path(args.output)
    iface_mgr  = InterfaceManager(args.interface)
    display    = TerminalDisplay(output_dir)
    saver      = HandshakeSaver(output_dir)
    capture    = HandshakeCapture(saver, display)

    if not iface_mgr.set_monitor_mode():
        sys.exit(1)

    hop_stop    = threading.Event()
    deauth_stop = threading.Event()
    stop_sniff  = threading.Event()

    def on_exit(sig, frame):
        hop_stop.set()
        deauth_stop.set()
        stop_sniff.set()
        iface_mgr.restore_managed_mode()
        total = sum(1 for h in capture.handshakes.values() if h.saved)
        print(f"\n[+] Handshakes guardados: {total}  →  {output_dir}/")
        sys.exit(0)

    signal.signal(signal.SIGINT,  on_exit)
    signal.signal(signal.SIGTERM, on_exit)

    if args.hop:
        threading.Thread(
            target=iface_mgr.channel_hopper, args=(hop_stop,), daemon=True
        ).start()
        print("[*] Channel hopping activado (500 ms/canal).")

    if args.deauth:
        print("[!] Deauth activado — asegúrate de tener autorización.")

        def _deauth_loop() -> None:
            while not deauth_stop.is_set():
                deauth_stop.wait(30)
                if deauth_stop.is_set():
                    break
                for bssid, info in list(capture.networks.items()):
                    hs = capture.handshakes.get(bssid)
                    if (hs is None or not hs.saved) and "WPA" in info.encryption:
                        capture.send_deauth(args.interface, bssid)

        threading.Thread(target=_deauth_loop, daemon=True).start()

    display.render(capture.networks, capture.handshakes, capture.eapol_sessions)
    print(f"[*] Escaneando en {args.interface}...\n")

    sniff(
        iface=args.interface,
        prn=capture.packet_handler,
        store=False,
        stop_filter=lambda _: stop_sniff.is_set(),
    )
