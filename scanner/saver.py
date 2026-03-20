"""
Generación y escritura de archivos .hc22000 y .pcap.
"""

from pathlib import Path
from typing import Dict, List, Tuple

from scapy.all import wrpcap

from .models import HandshakeData, NetworkInfo
from .parser import PacketParser


class HandshakeSaver:
    """Serializa handshakes capturados al formato hc22000 (hashcat -m 22000)."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    # ------------------------------------------------------------------ #
    #  Helpers internos                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _safe_name(s: str) -> str:
        return "".join(c if c.isalnum() or c in "-_" else "_" for c in s)

    @staticmethod
    def _mac_to_hex(mac: str) -> str:
        return mac.replace(":", "").replace("-", "").lower()

    def _line_pmkid(self, bssid: str, client: str, ssid: str, pmkid: bytes) -> str:
        return (
            f"WPA*01*{pmkid.hex()}"
            f"*{self._mac_to_hex(bssid)}"
            f"*{self._mac_to_hex(client)}"
            f"*{ssid.encode().hex()}"
            f"***"
        )

    def _line_eapol(
        self,
        bssid: str,
        client: str,
        ssid: str,
        anonce: bytes,
        eapol_m2: bytes,
        mic: bytes,
        msg_pair: int,
    ) -> str:
        return (
            f"WPA*02*{mic.hex()}"
            f"*{self._mac_to_hex(bssid)}"
            f"*{self._mac_to_hex(client)}"
            f"*{ssid.encode().hex()}"
            f"*{anonce.hex()}"
            f"*{PacketParser.eapol_zero_mic(eapol_m2).hex()}"
            f"*{msg_pair:02d}"
        )

    # ------------------------------------------------------------------ #
    #  API pública                                                         #
    # ------------------------------------------------------------------ #

    def save(
        self,
        bssid: str,
        hs: HandshakeData,
        networks: Dict[str, NetworkInfo],
    ) -> Tuple[bool, str, List[str]]:
        """
        Escribe el archivo .hc22000 (y .pcap si hay frames raw).
        Devuelve (guardado, ruta_hc22000, lista_de_tipos_guardados).
        Devuelve (False, "", []) si no hay material suficiente.
        """
        ssid  = networks[bssid].ssid if bssid in networks else bssid
        fname = f"{self._safe_name(ssid)}_{self._mac_to_hex(bssid)}"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        lines: List[str] = []
        types: List[str] = []

        if hs.pmkid is not None:
            lines.append(self._line_pmkid(bssid, hs.client, ssid, hs.pmkid))
            types.append("PMKID")

        if hs.anonce is not None and hs.eapol_m2 is not None and hs.mic is not None:
            lines.append(
                self._line_eapol(
                    bssid, hs.client, ssid,
                    hs.anonce, hs.eapol_m2, hs.mic, hs.msg_pair,
                )
            )
            types.append("EAPOL 4-way")

        if not lines:
            return False, "", []

        hc_path = self.output_dir / f"{fname}.hc22000"
        with open(hc_path, "w") as fh:
            fh.write("\n".join(lines) + "\n")

        if hs.frames:
            wrpcap(str(self.output_dir / f"{fname}.pcap"), hs.frames)

        return True, str(hc_path), types
