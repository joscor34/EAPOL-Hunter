"""
Modelos de datos para el scanner WiFi.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Union


@dataclass
class NetworkInfo:
    """Información de una red WiFi detectada via Beacon Frame."""

    ssid: str
    channel: int
    signal: Union[float, str]
    encryption: str


@dataclass
class HandshakeData:
    """Estado del handshake WPA capturado para un AP concreto."""

    client: str
    frames: List = field(default_factory=list)   # paquetes scapy raw
    saved: bool = False
    saved_path: str = ""

    # PMKID (msg1 Key Data)
    pmkid: Optional[bytes] = None

    # 4-way handshake
    anonce: Optional[bytes] = None
    eapol_m2: Optional[bytes] = None
    mic: Optional[bytes] = None
    msg_pair: int = 0   # 0 = M1+M2, 1 = M2+M3 (código hc22000)
