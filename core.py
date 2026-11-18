import base64
import json
import os
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote

ALLOWED_DOMAIN = "wikopvpn.site"
SOCKS_PORT = 10808
HTTP_PORT = 10809
DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "WikopVPN")


def is_allowed_url(url):
    """Только https и только wikopvpn.site (или его поддомены)."""
    try:
        u = urlparse(url.strip())
        host = (u.hostname or "").lower()
    except ValueError:
        return False
    return u.scheme == "https" and (host == ALLOWED_DOMAIN or host.endswith("." + ALLOWED_DOMAIN))


class _StrictRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_allowed_url(newurl):
            raise ValueError("Редирект на чужой сайт заблокирован")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _decode_body(raw):
    text = raw.decode("utf-8", "ignore").strip()
    if "://" in text:
        return text
    try:
        compact = "".join(text.split()).replace("-", "+").replace("_", "/")
        compact += "=" * (-len(compact) % 4)
        return base64.b64decode(compact).decode("utf-8", "ignore")
    except Exception:
        return text


def parse_vless(link):
    u = urlparse(link.strip())
    if u.scheme != "vless" or not u.username or not u.hostname or not u.port:
        raise ValueError("Некорректная vless-ссылка")
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    return {
        "name": unquote(u.fragment) or f"{u.hostname}:{u.port}",
        "uuid": unquote(u.username),
        "host": u.hostname,
        "port": u.port,
        "q": q,
    }


def fetch_subscription(url):
    url = url.strip()
    if not is_allowed_url(url):
        raise ValueError("Подписка должна быть с https://wikopvpn.site. Другие сайты не принимаются.")
    opener = urllib.request.build_opener(_StrictRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": "WikopVPN-Client/1.0"})
    with opener.open(req, timeout=20) as resp:
        if not is_allowed_url(resp.geturl()):
            raise ValueError("Подписка пришла не с wikopvpn.site")
        raw = resp.read(2_000_000)
    servers = []
    for line in _decode_body(raw).splitlines():
        line = line.strip()
        if line.startswith("vless://"):
            try:
                servers.append(parse_vless(line))
            except ValueError:
                continue
    if not servers:
        raise ValueError("В подписке нет поддерживаемых VLESS-серверов")
    return servers


def build_config(server):
    q = server["q"]
    net = q.get("type", "tcp")
    sec = q.get("security", "none")
    stream = {"network": net, "security": sec}

    if sec == "reality":
        stream["realitySettings"] = {
            "serverName": q.get("sni", ""),
            "fingerprint": q.get("fp", "chrome"),
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", ""),
        }
    elif sec == "tls":
        tls = {
            "serverName": q.get("sni") or q.get("host") or server["host"],
            "fingerprint": q.get("fp", "chrome"),
        }
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        stream["tlsSettings"] = tls

    if net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": q.get("serviceName", ""),
            "multiMode": q.get("mode") == "multi",
        }
    elif net == "xhttp":
        x = {"path": q.get("path", "/")}
        if q.get("host"):
            x["host"] = q["host"]
        if q.get("mode"):
            x["mode"] = q["mode"]
        if q.get("extra"):
            try:
                x["extra"] = json.loads(q["extra"])
            except ValueError:
                pass
        stream["xhttpSettings"] = x

    user = {"id": server["uuid"], "encryption": q.get("encryption", "none")}
    if q.get("flow"):
        user["flow"] = q["flow"]

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
             "settings": {"udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": HTTP_PORT, "protocol": "http"},
        ],
        "outbounds": [
            {"tag": "proxy", "protocol": "vless",
             "settings": {"vnext": [{"address": server["host"], "port": server["port"], "users": [user]}]},
             "streamSettings": stream},
            {"tag": "direct", "protocol": "freedom"},
        ],
    }


def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def _set_proxy(enable, server="", override=""):
    if os.name != "nt":
        return None
    import winreg
    import ctypes
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                         r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                         0, winreg.KEY_READ | winreg.KEY_WRITE)
    try:
        prev = {}
        for n in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
            try:
                prev[n] = winreg.QueryValueEx(key, n)
            except OSError:
                prev[n] = None
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
        if server:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
        if override:
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, override)
    finally:
        winreg.CloseKey(key)
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(0, 39, 0, 0)
    wininet.InternetSetOptionW(0, 37, 0, 0)
    return prev


def _restore_proxy(prev):
    if os.name != "nt" or not prev:
        return
    import winreg
    import ctypes
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                         r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                         0, winreg.KEY_WRITE)
    try:
        for name, val in prev.items():
            if val is None:
                if name == "ProxyEnable":
                    winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, 0)
            else:
                winreg.SetValueEx(key, name, 0, val[1], val[0])
    finally:
        winreg.CloseKey(key)
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(0, 39, 0, 0)
    wininet.InternetSetOptionW(0, 37, 0, 0)


class Vpn:
    def __init__(self):
        self.proc = None
        self.prev_proxy = None
        self.log_path = os.path.join(DATA_DIR, "xray.log")

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def connect(self, server):
        exe = os.path.join(app_dir(), "xray.exe")
        if not os.path.exists(exe):
            raise FileNotFoundError("Не найден xray.exe рядом с программой")
        os.makedirs(DATA_DIR, exist_ok=True)
        cfg = os.path.join(DATA_DIR, "config.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump(build_config(server), f, ensure_ascii=False, indent=2)
        log = open(self.log_path, "w", encoding="utf-8")
        flags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
        self.proc = subprocess.Popen([exe, "run", "-c", cfg], cwd=app_dir(),
                                     stdout=log, stderr=log, creationflags=flags)
        time.sleep(1.0)
        if self.proc.poll() is not None:
            self.proc = None
            raise RuntimeError(f"Xray не запустился. Лог: {self.log_path}")
        self.prev_proxy = _set_proxy(True, f"127.0.0.1:{HTTP_PORT}",
                                     "localhost;127.*;10.*;192.168.*;<local>")

    def disconnect(self):
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            self.proc = None
        _restore_proxy(self.prev_proxy)
        self.prev_proxy = None
