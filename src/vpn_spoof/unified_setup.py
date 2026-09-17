import http.server
import ssl
import json
import threading
import time
import sys
import socket
from pathlib import Path
from typing import Optional, Set
from rich.console import Console

from .net_utils import get_best_local_ip, get_all_ip_addresses
from .qr_utils import print_qr_banner
from .cert_utils import generate_self_signed_cert
from .config_store import ConfigStore
from .key_listener import wait_for_cancel

DATA_DIR = Path(__file__).absolute().parent.parent.parent / "data"
CERT_FILE = DATA_DIR / "cert.pem"
KEY_FILE = DATA_DIR / "key.pem"

console = Console(legacy_windows=False)

class ReusableHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True

def find_available_port(start_port: int, max_tries: int = 50, exclude_ports: Optional[Set[int]] = None) -> int:
    """Find an available TCP port on 0.0.0.0 starting from start_port."""
    excludes = exclude_ports or set()
    for port in range(start_port, start_port + max_tries):
        if port in excludes:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                return port
        except OSError:
            continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]

HTML_PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>VPN Spoof Setup</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #0b1120; color: #f8fafc; padding: 20px 12px; display: flex; justify-content: center; min-height: 100vh; }
        .container { max-width: 460px; width: 100%; }
        
        .header { text-align: center; margin-bottom: 20px; padding: 8px; }
        .header h1 { font-size: 20px; font-weight: 700; color: #38bdf8; margin-bottom: 4px; letter-spacing: -0.5px; }
        .header p { font-size: 13px; color: #94a3b8; }

        .card { background: #1e293b; border-radius: 12px; padding: 16px; margin-bottom: 14px; border: 1px solid #334155; }
        .card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
        .card-title { font-size: 15px; font-weight: 600; color: #e2e8f0; display: flex; align-items: center; gap: 8px; }
        .step-num { display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; background: #0284c7; color: #fff; border-radius: 6px; font-size: 12px; font-weight: bold; }
        
        .badge { font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 6px; }
        .badge-wait { background: #334155; color: #94a3b8; }
        .badge-active { background: #854d0e; color: #fef08a; }
        .badge-done { background: #166534; color: #4ade80; }

        .input-box { width: 100%; padding: 12px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font-size: 14px; margin-bottom: 10px; outline: none; }
        .input-box:focus { border-color: #38bdf8; }

        .btn { display: inline-flex; align-items: center; justify-content: center; width: 100%; padding: 12px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; border: none; text-decoration: none; transition: all 0.15s; }
        .btn:active { transform: scale(0.98); }
        .btn-primary { background: #0284c7; color: #fff; }
        .btn-success { background: #16a34a; color: #fff; }
        .btn-secondary { background: #334155; color: #cbd5e1; }

        .tabs { display: flex; gap: 6px; background: #0f172a; padding: 4px; border-radius: 8px; margin-bottom: 10px; border: 1px solid #334155; }
        .tab-btn { flex: 1; padding: 6px; border: none; background: transparent; color: #94a3b8; font-size: 12px; font-weight: 600; border-radius: 6px; cursor: pointer; }
        .tab-btn.active { background: #1e293b; color: #38bdf8; }
        
        .tab-content { display: none; font-size: 12px; color: #94a3b8; line-height: 1.5; background: #0f172a; padding: 10px 12px; border-radius: 8px; margin-bottom: 10px; border: 1px solid #1e293b; }
        .tab-content.active { display: block; }
        .tab-content ol { padding-left: 18px; }
        .tab-content li { margin-bottom: 3px; }

        .status-box { font-size: 12px; margin-top: 8px; min-height: 18px; text-align: center; }
        .status-ok { color: #4ade80; font-weight: 600; }
        .status-err { color: #f87171; }

        .done-banner { display: none; background: #14532d; border: 1px solid #22c55e; border-radius: 12px; padding: 16px; text-align: center; margin-top: 14px; }
        .done-banner h3 { color: #4ade80; font-size: 16px; margin-bottom: 4px; }
        .done-banner p { color: #bbf7d0; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>VPN Spoof Setup</h1>
            <p>Текущая сессия привязки устройства к ПК</p>
        </div>

        <!-- 1. URL -->
        <div class="card" id="cardUrl">
            <div class="card-header">
                <div class="card-title">
                    <span class="step-num">1</span>
                    <span>Ссылка подписки</span>
                </div>
                <span class="badge badge-wait" id="badgeUrl">Ожидание</span>
            </div>
            <div id="bodyUrl">
                <form id="urlForm" onsubmit="return false;">
                    <input type="text" class="input-box" id="urlInput" 
                           placeholder="Вставьте ссылку подписки (https://...)" 
                           autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
                    <button class="btn btn-primary" id="btnSendUrl" type="button">Отправить на ПК</button>
                </form>
                <div class="status-box" id="statusUrl"></div>
            </div>
        </div>

        <!-- 2. Certificate -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span class="step-num">2</span>
                    <span>Сертификат CA</span>
                </div>
                <span class="badge badge-wait">Для перехвата</span>
            </div>
            
            <div class="tabs">
                <button class="tab-btn active" onclick="switchTab('ios')">Apple iOS</button>
                <button class="tab-btn" onclick="switchTab('android')">Android</button>
            </div>

            <div id="tab-ios" class="tab-content active">
                <ol>
                    <li>Нажмите кнопку ниже и скачайте профиль.</li>
                    <li>Откройте <b>Настройки</b> &rarr; <b>Профиль загружен</b> &rarr; <b>Установить</b>.</li>
                    <li><b>Настройки</b> &rarr; <b>Основные</b> &rarr; <b>Об этом устройстве</b> &rarr; <b>Доверие сертификатам</b> &rarr; включите тумблер.</li>
                </ol>
            </div>

            <div id="tab-android" class="tab-content">
                <ol>
                    <li>Нажмите кнопку ниже и скачайте файл сертификата.</li>
                    <li>Откройте <b>Настройки</b> &rarr; <b>Безопасность</b> (или «Шифрование и учетные данные»).</li>
                    <li>Выберите <b>Установка из памяти</b> &rarr; <b>Сертификат CA</b> (установите «В любом случае»).</li>
                </ol>
            </div>

            <a href="/cert.pem" class="btn btn-secondary">Скачать сертификат (cert.pem)</a>
        </div>

        <!-- 3. Client Headers -->
        <div class="card" id="cardHapp">
            <div class="card-header">
                <div class="card-title">
                    <span class="step-num">3</span>
                    <span>Привязка клиента (VLESS / ядра)</span>
                </div>
                <span class="badge badge-wait" id="badgeHapp">Ожидание запроса</span>
            </div>
            <div id="bodyHapp">
                <p style="font-size:12px; color:#94a3b8; margin-bottom:10px;">
                    Скопируйте ссылку и добавьте её в ваш VPN-клиент (<b>Happ, sing-box, FlClash, v2rayN и др.</b>) для однократного обновления:
                </p>
                <button class="btn btn-success" id="btnCopyHapp" type="button">Скопировать ссылку для клиента</button>
                <div class="status-box" id="statusHapp"></div>
            </div>
        </div>

        <div class="done-banner" id="doneBanner">
            <h3>Все данные получены!</h3>
            <p>ПК сохранил ссылку и заголовки клиента (VLESS / ядра). Окно можно закрыть.</p>
        </div>
    </div>

    <script>
        const SUB_URL = "{{SUB_URL}}";

        function switchTab(platform) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            if (platform === 'ios') {
                document.querySelectorAll('.tab-btn')[0].classList.add('active');
                document.getElementById('tab-ios').classList.add('active');
            } else {
                document.querySelectorAll('.tab-btn')[1].classList.add('active');
                document.getElementById('tab-android').classList.add('active');
            }
        }

        // 1. URL submit (STRICTLY ON BUTTON CLICK OR ENTER)
        const btnSendUrl = document.getElementById('btnSendUrl');
        const urlInput = document.getElementById('urlInput');
        const statusUrl = document.getElementById('statusUrl');
        const badgeUrl = document.getElementById('badgeUrl');

        async function submitUrl() {
            const url = (urlInput.value || '').trim();
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                statusUrl.className = 'status-box status-err';
                statusUrl.textContent = 'Введите корректную ссылку подписки (начинается с http/https)';
                return;
            }
            btnSendUrl.disabled = true;
            statusUrl.className = 'status-box';
            statusUrl.textContent = 'Отправка на ПК...';
            try {
                const res = await fetch('/api/submit-url', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                const d = await res.json();
                if (d.status === 'ok') {
                    markUrlDone();
                } else {
                    btnSendUrl.disabled = false;
                    statusUrl.className = 'status-box status-err';
                    statusUrl.textContent = 'Ошибка сервера при сохранении';
                }
            } catch (e) {
                btnSendUrl.disabled = false;
                statusUrl.className = 'status-box status-err';
                statusUrl.textContent = 'Ошибка связи с ПК';
            }
        }

        function markUrlDone() {
            badgeUrl.className = 'badge badge-done';
            badgeUrl.textContent = 'Получено';
            document.getElementById('bodyUrl').innerHTML = '<div class="status-box status-ok">Ссылка подписки успешно принята ПК</div>';
            checkAllDone();
        }

        btnSendUrl.addEventListener('click', submitUrl);
        urlInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                submitUrl();
            }
        });

        // 3. Copy Happ link
        const btnCopyHapp = document.getElementById('btnCopyHapp');
        const statusHapp = document.getElementById('statusHapp');
        const badgeHapp = document.getElementById('badgeHapp');

        btnCopyHapp.addEventListener('click', async () => {
            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(SUB_URL);
                } else {
                    const el = document.createElement('textarea');
                    el.value = SUB_URL;
                    document.body.appendChild(el);
                    el.select();
                    document.execCommand('copy');
                    document.body.removeChild(el);
                }
                statusHapp.className = 'status-box status-ok';
                statusHapp.innerHTML = 'Ссылка скопирована! Вставьте ее в VPN-клиент (Happ, sing-box и др.) и обновите подписку.';
                badgeHapp.className = 'badge badge-active';
                badgeHapp.textContent = 'Ожидание клиента...';
            } catch (err) {
                statusHapp.className = 'status-box';
                statusHapp.innerHTML = '<small style="word-break:break-all;color:#38bdf8;">' + SUB_URL + '</small>';
            }
        });

        function markHappDone() {
            badgeHapp.className = 'badge badge-done';
            badgeHapp.textContent = 'Перехвачено';
            document.getElementById('bodyHapp').innerHTML = '<div class="status-box status-ok">Заголовки клиента (VLESS / ядра) успешно перехвачены</div>';
            checkAllDone();
        }

        function checkAllDone() {
            if (badgeUrl.textContent === 'Получено' && badgeHapp.textContent === 'Перехвачено') {
                document.getElementById('doneBanner').style.display = 'block';
            }
        }

        // Poll status from server ONLY FOR CURRENT SESSION
        setInterval(async () => {
            try {
                const res = await fetch('/api/status');
                const st = await res.json();
                if (st.has_url && badgeUrl.textContent !== 'Получено') {
                    markUrlDone();
                }
                if (st.has_headers && badgeHapp.textContent !== 'Перехвачено') {
                    markHappDone();
                }
            } catch (e) {}
        }, 1500);
    </script>
</body>
</html>
"""

class UnifiedSetupServer:
    def __init__(self, http_port: int = 8080, https_port: int = 8443, ip: Optional[str] = None):
        self.http_port = http_port
        self.https_port = https_port
        self.ip = ip or get_best_local_ip()
        self.config_store = ConfigStore()
        self.stop_event = threading.Event()
        
        # FRESH SESSION: ALWAYS False on start of item [1]!
        self.has_url = False
        self.has_headers = False
        self.received_url = None
        self.received_headers = None

    def log(self, level: str, msg: str):
        now = time.strftime("%H:%M:%S")
        if level == "INFO":
            console.print(f"[dim]{now}[/dim] [bold blue][INFO][/bold blue] {msg}")
        elif level == "OK":
            console.print(f"[dim]{now}[/dim] [bold green][OK][/bold green]   {msg}")
        elif level == "WAIT":
            console.print(f"[dim]{now}[/dim] [bold yellow][WAIT][/bold yellow] {msg}")
        elif level == "DONE":
            console.print(f"[dim]{now}[/dim] [bold cyan][DONE][/bold cyan] {msg}")

    def create_http_handler(self):
        parent = self
        sub_url = f"https://{self.ip}:{self.https_port}/sub"
        page_html = HTML_PAGE.replace("{{SUB_URL}}", sub_url)

        class HTTPHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path in ["/cert.pem", "/cert", "/ca.crt"]:
                    if not CERT_FILE.exists():
                        self.send_error(404, "Certificate not ready")
                        return
                    with open(CERT_FILE, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-x509-ca-cert")
                    self.send_header("Content-Disposition", 'attachment; filename="vpn_spoof_ca.pem"')
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    parent.log("INFO", f"Телефон ({self.client_address[0]}) скачал сертификат CA")

                elif self.path == "/api/status":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    st = json.dumps({"has_url": parent.has_url, "has_headers": parent.has_headers})
                    self.wfile.write(st.encode())

                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(page_html.encode("utf-8"))
                    parent.log("INFO", f"Телефон ({self.client_address[0]}) открыл страницу настройки")

            def do_POST(self):
                if self.path == "/api/submit-url":
                    length = int(self.headers.get("Content-Length", 0))
                    body = self.rfile.read(length)
                    try:
                        data = json.loads(body.decode("utf-8"))
                        url = data.get("url")
                        if url:
                            parent.received_url = url
                            parent.has_url = True
                            parent.config_store.update_target_url(url)
                            parent.log("OK", f"Ссылка подписки успешно получена: {url[:45]}...")
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status":"ok"}')
                            parent.check_completion()
                            return
                    except Exception as e:
                        parent.log("INFO", f"Ошибка обработки URL: {e}")
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"status":"error"}')

            def log_message(self, format, *args):
                return
        return HTTPHandler

    def create_https_handler(self):
        parent = self
        class HTTPSHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                headers = dict(self.headers)
                hwid = headers.get("X-HWID") or headers.get("x-hwid")
                ua = headers.get("User-Agent") or headers.get("user-agent")

                parent.log("OK", f"Клиент подключился ({self.client_address[0]})!")
                if hwid:
                    parent.log("OK", f"X-HWID: {hwid}")
                if ua:
                    parent.log("INFO", f"User-Agent: {ua}")

                saved = {}
                for k, v in headers.items():
                    if k.lower().startswith("x-") or k.lower() in ["user-agent", "accept-language", "accept"]:
                        saved[k] = v

                parent.received_headers = saved
                parent.has_headers = True
                parent.config_store.update_headers(saved)

                dummy = b"proxies: []\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/yaml; charset=utf-8")
                self.send_header("subscription-userinfo", "upload=0; download=0; total=1073741824000; expire=2000000000")
                self.send_header("profile-update-interval", "24")
                self.end_headers()
                self.wfile.write(dummy)

                parent.check_completion()

            def log_message(self, format, *args):
                return
        return HTTPSHandler

    def check_completion(self):
        if self.has_url and self.has_headers:
            self.log("DONE", "Все данные успешно собраны и сохранены в data/config.json!")
            threading.Thread(target=self.delayed_shutdown).start()

    def delayed_shutdown(self):
        time.sleep(1.5)
        self.stop_event.set()

    def run(self):
        # 1. Certificate check
        all_ips = list(set(get_all_ip_addresses() + [self.ip]))
        if not CERT_FILE.exists() or not KEY_FILE.exists():
            generate_self_signed_cert(CERT_FILE, KEY_FILE, all_ips)
            self.log("OK", "Локальный SSL-сертификат сгенерирован")
        else:
            self.log("OK", "Локальный SSL-сертификат готов")

        # Automatically find available ports if defaults (8080 / 8443) are busy
        chosen_http = find_available_port(self.http_port)
        if chosen_http != self.http_port:
            self.log("INFO", f"Порт {self.http_port} занят, автоматически выбран свободный порт {chosen_http}")
            self.http_port = chosen_http

        chosen_https = find_available_port(self.https_port, exclude_ports={self.http_port})
        if chosen_https != self.https_port:
            self.log("INFO", f"Порт {self.https_port} занят, автоматически выбран свободный порт {chosen_https}")
            self.https_port = chosen_https

        # 2. HTTP server
        httpd = ReusableHTTPServer(("0.0.0.0", self.http_port), self.create_http_handler())
        http_t = threading.Thread(target=httpd.serve_forever)
        http_t.daemon = True
        http_t.start()

        # 3. HTTPS server
        httpsd = ReusableHTTPServer(("0.0.0.0", self.https_port), self.create_https_handler())
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
        httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
        https_t = threading.Thread(target=httpsd.serve_forever)
        https_t.daemon = True
        https_t.start()

        setup_url = f"http://{self.ip}:{self.http_port}/"

        console.print("\n" + "=" * 62)
        console.print("       ЕДИНАЯ НАСТРОЙКА: ССЫЛКА + СЕРТИФИКАТ + КЛИЕНТ")
        console.print("=" * 62 + "\n")
        print_qr_banner("ОТСКАНИРУЙТЕ QR-КОД КАМЕРОЙ ТЕЛЕФОНА", setup_url)
        console.print(f"Адрес: [bold cyan]{setup_url}[/bold cyan]")
        console.print("Отсканируйте код. На странице вставьте ссылку и обновите профиль в клиенте.\n")
        console.print("[dim]Нажмите [bold yellow]q[/bold yellow] для возврата в главное меню | [bold red]Ctrl+C[/bold red] для выхода из программы[/dim]\n")

        self.log("WAIT", "Ожидание действий с телефона...")

        try:
            res = wait_for_cancel(self.stop_event)
            if res == 'back':
                console.print("\n[yellow]Возврат в главное меню...[/yellow]")
        finally:
            httpd.shutdown()
            httpsd.shutdown()
            httpd.server_close()
            httpsd.server_close()

        return self.has_url and self.has_headers

def main():
    s = UnifiedSetupServer()
    s.run()

if __name__ == "__main__":
    main()
