"""
Interfaz de usuario en terminal: tabla de redes y log de eventos.
"""

import os
import time
from pathlib import Path
from typing import Dict

from .models import HandshakeData, NetworkInfo


class TerminalDisplay:
    """Renderiza la tabla de redes y el log de eventos en la terminal."""

    MAX_LOG_LINES = 6
    WIDTH = 112

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self._events_log: list = []

    # ------------------------------------------------------------------ #
    #  Log de eventos                                                      #
    # ------------------------------------------------------------------ #

    def log_event(self, msg: str) -> None:
        """Añade un evento con timestamp al log visible al pie de pantalla."""
        ts = time.strftime("%H:%M:%S")
        self._events_log.append(f"  \033[90m[{ts}]\033[0m {msg}")
        if len(self._events_log) > self.MAX_LOG_LINES:
            del self._events_log[0]

    # ------------------------------------------------------------------ #
    #  Estado del handshake para una red                                   #
    # ------------------------------------------------------------------ #

    def hs_status(
        self,
        bssid: str,
        handshakes: Dict[str, HandshakeData],
        eapol_sessions: dict,
    ) -> str:
        hs = handshakes.get(bssid)
        if hs is None:
            return "\033[90m—\033[0m"
        if hs.saved:
            fname = Path(hs.saved_path).name if hs.saved_path else "archivo"
            return f"\033[32m✔ GUARDADO → {fname}\033[0m"

        parts = []
        if hs.pmkid is not None:
            parts.append("PMKID")

        eapol_msgs: set = set()
        for (ap, _cl), session in eapol_sessions.items():
            if ap == bssid:
                eapol_msgs |= set(session.keys())

        if eapol_msgs:
            msgs_str = "+".join(f"M{n}" for n in sorted(eapol_msgs))
            label = f"EAPOL({msgs_str})" if hs.anonce is not None else f"EAPOL({msgs_str} incompleto)"
            parts.append(label)

        if parts:
            return f"\033[33m⚡ {' | '.join(parts)}\033[0m"
        return "\033[90m—\033[0m"

    # ------------------------------------------------------------------ #
    #  Renderizado de la tabla completa                                    #
    # ------------------------------------------------------------------ #

    def render(
        self,
        networks: Dict[str, NetworkInfo],
        handshakes: Dict[str, HandshakeData],
        eapol_sessions: dict,
    ) -> None:
        os.system("clear")

        total_hs  = sum(1 for h in handshakes.values() if h.saved)
        total_cap = sum(
            1 for h in handshakes.values()
            if h.anonce is not None or h.pmkid is not None
        )

        W = self.WIDTH
        print("=" * W)
        print("  WiFi Scanner + Handshake Extractor (hc22000)                   Ctrl+C para salir")
        print("=" * W)
        print(f"  {'BSSID':<20}  {'SSID':<26}  {'CH':<4}  {'dBm':<6}  {'Cifrado':<12}  Estado")
        print("  " + "-" * (W - 4))

        def _sig(item):
            s = item[1].signal
            return s if isinstance(s, (int, float)) else -999

        for bssid, info in sorted(networks.items(), key=_sig, reverse=True):
            print(
                f"  {bssid:<20}  {info.ssid[:26]:<26}  {info.channel:<4}  "
                f"{str(info.signal):<6}  {info.encryption:<12}  "
                f"{self.hs_status(bssid, handshakes, eapol_sessions)}"
            )

        print("=" * W)
        RST   = "\033[0m"
        s_col = "\033[32m" if total_hs  else "\033[0m"
        c_col = "\033[33m" if total_cap else "\033[0m"
        print(
            f"  Redes: {len(networks)}   "
            f"Capturando: {c_col}{total_cap}{RST}   "
            f"Guardados: {s_col}{total_hs}{RST}   "
            f"Salida: \033[36m{self.output_dir}/\033[0m"
        )

        if self._events_log:
            print("-" * W)
            for line in self._events_log:
                print(line)
        print("=" * W)
