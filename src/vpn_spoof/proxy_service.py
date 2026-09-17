import http.server
import urllib.request
import urllib.error
import ssl
import sys
import threading
from pathlib import Path
from typing import Optional

from .config_store import ConfigStore
from .key_listener import wait_for_cancel

DATA_DIR = Path(__file__).absolute().parent.parent.parent / "data"
DUMP_PATH = DATA_DIR / "last_response.yaml"

class ReusableHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True

class SpoofProxyServer:
    def __init__(self, listen_port: int = 54321, host: str = "127.0.0.1"):
        self.listen_port = listen_port
        self.host = host
        self.config_store = ConfigStore()

    def create_handler(self):
        parent = self
        class SpoofHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                cfg = parent.config_store.load()
                target_url = cfg.get("target_url")
                headers = cfg.get("headers", {})

                if not target_url:
                    self.send_error(500, "Target URL missing in config.json. Run link capture first.")
                    return

                print(f"[*] Forwarding request with HWID: {headers.get('X-HWID', 'N/A')} and UA: {headers.get('User-Agent', 'N/A')}")

                req = urllib.request.Request(target_url, headers=headers)
                
                try:
                    ctx = ssl.create_default_context()
                    with urllib.request.urlopen(req, context=ctx, timeout=20) as response:
                        content = response.read()
                        status = response.status

                        print(f"[+] Target responded: HTTP {status}, payload size: {len(content)} bytes")

                        try:
                            with open(DUMP_PATH, "wb") as f_dump:
                                f_dump.write(content)
                        except Exception:
                            pass

                        self.send_response(status)
                        for h in ["Content-Type", "subscription-userinfo", "profile-update-interval", "Subscription-UserInfo"]:
                            if h_val := response.headers.get(h):
                                self.send_header(h, h_val)
                        
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                        self.wfile.write(content)
                        print("[+] Profile served to client successfully\n")

                except urllib.error.HTTPError as e:
                    print(f"[-] Target returned HTTP {e.code}")
                    self.send_response(e.code)
                    self.end_headers()
                    self.wfile.write(e.read())
                except Exception as e:
                    print(f"[-] Forwarding error: {e}")
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(str(e).encode())

            def log_message(self, format, *args):
                return
        return SpoofHandler

    def run(self):
        handler = self.create_handler()
        try:
            server = ReusableHTTPServer((self.host, self.listen_port), handler)
        except OSError as e:
            if getattr(e, 'errno', None) == 98 or "already in use" in str(e).lower():
                print(f"\n[-] Ошибка: Порт {self.listen_port} уже занят другим процессом!")
                print(f"[-] Возможно, фоновая служба автозапуска уже работает. Проверьте статус в меню [2].\n")
                return
            raise

        print(f"[*] VPN Spoof Proxy is running on http://{self.host}:{self.listen_port}")
        print(f"[!] Point your VPN client (FlClash/v2rayN/Sing-box) to: http://{self.host}:{self.listen_port}/sub\n")
        print("Нажмите 'q' для возврата в меню | Ctrl+C для выхода из программы...\n")

        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        stop_ev = threading.Event()
        try:
            import signal
            def _sig_handler(signum, frame):
                stop_ev.set()
            signal.signal(signal.SIGTERM, _sig_handler)
            signal.signal(signal.SIGINT, _sig_handler)
        except Exception:
            pass

        try:
            res = wait_for_cancel(stop_ev)
            if res == 'back':
                print("\n[!] Остановка прокси и возврат в главное меню...")
        finally:
            server.shutdown()
            server.server_close()

def main():
    proxy = SpoofProxyServer()
    proxy.run()

if __name__ == "__main__":
    main()
