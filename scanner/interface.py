"""
Gestión de la interfaz WiFi: modo monitor/managed y salto de canal.
"""

import subprocess
import threading
from typing import List

CHANNELS: List[int] = (
    list(range(1, 14))  # 2.4 GHz
    + [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
       116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]  # 5 GHz
)


class InterfaceManager:
    """Controla el modo de operación y el canal de la interfaz WiFi."""

    def __init__(self, iface: str) -> None:
        self.iface = iface

    def _run(self, cmd: List[str]) -> bool:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[-] Error: {' '.join(cmd)}: {r.stderr.strip()}")
            return False
        return True

    def set_monitor_mode(self) -> bool:
        """Pone la interfaz en modo monitor. Devuelve False si falla."""
        print(f"[*] Configurando {self.iface} en modo monitor...")
        for cmd in [
            ["ip", "link", "set", self.iface, "down"],
            ["iw", self.iface, "set", "monitor", "none"],
            ["ip", "link", "set", self.iface, "up"],
        ]:
            if not self._run(cmd):
                return False
        print(f"[+] {self.iface} en modo monitor.\n")
        return True

    def restore_managed_mode(self) -> None:
        """Restaura la interfaz a modo managed (llamado al salir)."""
        print(f"\n[*] Restaurando {self.iface} a modo managed...")
        for cmd in [
            ["ip", "link", "set", self.iface, "down"],
            ["iw", self.iface, "set", "type", "managed"],
            ["ip", "link", "set", self.iface, "up"],
        ]:
            subprocess.run(cmd, capture_output=True)
        print(f"[+] {self.iface} restaurada a modo managed.")

    def set_channel(self, channel: int) -> None:
        subprocess.run(
            ["iw", "dev", self.iface, "set", "channel", str(channel)],
            capture_output=True,
        )

    def channel_hopper(self, stop_event: threading.Event) -> None:
        """Rota entre canales 2.4/5 GHz cada 500 ms para maximizar cobertura."""
        idx = 0
        while not stop_event.is_set():
            self.set_channel(CHANNELS[idx % len(CHANNELS)])
            idx += 1
            stop_event.wait(0.5)
