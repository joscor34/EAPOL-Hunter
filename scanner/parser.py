"""
Parseo de frames 802.11 (Beacon) y EAPOL Key (IEEE 802.11i).
"""

import struct
from typing import Dict, Optional

from scapy.layers.dot11 import Dot11Elt


class PacketParser:
    """Utilidades estáticas para extraer información de frames WiFi y EAPOL."""

    # ------------------------------------------------------------------ #
    #  Beacon helpers                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
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
            elt = (
                elt.payload.getlayer(Dot11Elt)
                if hasattr(elt.payload, "getlayer")
                else None
            )
        if rsn:
            return "WPA2/WPA3"
        if wpa:
            return "WPA"
        if privacy:
            return "WEP"
        return "Abierta"

    @staticmethod
    def get_channel(pkt) -> int:
        elt = pkt.getlayer(Dot11Elt)
        while elt and isinstance(elt, Dot11Elt):
            if elt.ID == 3 and elt.info:
                try:
                    return elt.info[0]
                except (IndexError, TypeError):
                    pass
            elt = (
                elt.payload.getlayer(Dot11Elt)
                if hasattr(elt.payload, "getlayer")
                else None
            )
        return 0

    # ------------------------------------------------------------------ #
    #  EAPOL Key parsing                                                   #
    #                                                                      #
    #  Estructura del frame EAPOL-Key (offsets desde el inicio del PDU):  #
    #   [0]      EAPOL version                                             #
    #   [1]      EAPOL type  (3 = Key)                                     #
    #   [2:4]    EAPOL length                                              #
    #   [4]      Descriptor Type  (2=RSN, 254=WPA1)                       #
    #   [5:7]    Key Information flags                                     #
    #   [17:49]  Key Nonce  (ANonce en msg1/3, SNonce en msg2/4)          #
    #   [81:97]  Key MIC  (se pone a cero para el hash hashcat)           #
    #   [97:99]  Key Data Length                                           #
    #   [99:]    Key Data  (contiene el PMKID en msg1)                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def parse_eapol_key(raw_eapol: bytes) -> Optional[Dict]:
        """
        Parsea un frame EAPOL Key del 4-way handshake WPA.
        Devuelve un dict con msg_num, nonce, mic, key_data y raw,
        o None si el frame no es válido o no es pairwise.
        """
        if len(raw_eapol) < 99:
            return None
        if raw_eapol[1] != 3:               # EAPOL type = Key
            return None
        if raw_eapol[4] not in (1, 2, 254): # descriptor RSN / WPA1
            return None

        key_info = struct.unpack(">H", raw_eapol[5:7])[0]
        pairwise = bool(key_info & (1 << 3))
        ack      = bool(key_info & (1 << 7))
        mic      = bool(key_info & (1 << 8))
        secure   = bool(key_info & (1 << 9))

        if not pairwise:
            return None  # Group key — no es el handshake de autenticación

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

        nonce    = raw_eapol[17:49]
        mic_b    = raw_eapol[81:97]
        kd_len   = struct.unpack(">H", raw_eapol[97:99])[0]
        key_data = raw_eapol[99: 99 + kd_len] if len(raw_eapol) >= 99 + kd_len else b""

        return {
            "msg_num":  msg_num,
            "nonce":    nonce,
            "mic":      mic_b,
            "key_data": key_data,
            "raw":      raw_eapol,
        }

    @staticmethod
    def extract_pmkid(key_data: bytes) -> Optional[bytes]:
        """
        Busca el PMKID KDE en el Key Data del EAPOL msg1.
        Formato KDE: 0xDD | length(1) | OUI(3) | type(1) | data
        PMKID KDE:   OUI=00:0F:AC, type=4, data=16 bytes
        """
        i = 0
        while i + 2 <= len(key_data):
            tag = key_data[i]
            if tag == 0x00:
                i += 1
                continue
            if tag != 0xDD:
                break
            kde_len = key_data[i + 1]
            if i + 2 + kde_len > len(key_data):
                break
            body = key_data[i + 2: i + 2 + kde_len]
            if len(body) >= 20 and body[:3] == b"\x00\x0f\xac" and body[3] == 4:
                return body[4:20]  # 16 bytes de PMKID
            i += 2 + kde_len
        return None

    @staticmethod
    def eapol_zero_mic(raw_eapol: bytes) -> bytes:
        """Devuelve el frame EAPOL con el campo MIC (offsets 81-96) puesto a cero."""
        if len(raw_eapol) < 97:
            return raw_eapol
        return raw_eapol[:81] + b"\x00" * 16 + raw_eapol[97:]
