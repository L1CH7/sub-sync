import http.server
import ssl
import json
import threading
import time
import sys
from pathlib import Path
from typing import Dict, Any, Optional

from .net_utils import get_best_local_ip, get_all_ip_addresses
from .qr_utils import print_qr_banner, render_solid_terminal_qr
from .cert_utils import generate_self_signed_cert, ensure_cert_exists
from .config_store import ConfigStore

DATA_DIR = Path(__file__).absolute().parent.parent.parent / "data"
CERT_FILE = DATA_DIR / "cert.pem"
KEY_FILE = DATA_DIR / "key.pem"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>VPN Spoof - Шаг 2: Подключение Happ</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
        .card { background: #1e293b; border-radius: 20px; padding: 26px; max-width: 440px; width: 100%; box-shadow: 0 16px 36px rgba(0,0,0,0.6); text-align: center; border: 1px solid #334155; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; background: #0284c7; color: #f0f9ff; margin-bottom: 12px; text-transform: uppercase; }
        h2 { font-size: 22px; margin-bottom: 8px; color: #38bdf8; }
        p { font-size: 14px; color: #94a3b8; margin-bottom: 20px; line-height: 1.5; }
        .btn { display: flex; align-items: center; justify-content: center; gap: 8px; width: 100%; padding: 16px; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.2s; text-decoration: none; }
        .btn-cert { background: #0284c7; color: #f0f9ff; margin-bottom: 6px; box-shadow: 0 4px 14px rgba(2,132,199,0.3); }
        .btn-cert:active { transform: scale(0.98); background: #0369a1; }
        .cert-hint { font-size: 12px; color: #64748b; margin-bottom: 18px; text-align: left; line-height: 1.4; background: #0f172a; padding: 10px 14px; border-radius: 8px; border: 1px solid #1e293b; }
        .divider { display: flex; align-items: center; text-align: center; color: #64748b; font-size: 12px; margin: 14px 0; }
        .divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid #334155; }
        .divider:not(:empty)::before { margin-right: .5em; }
        .divider:not(:empty)::after { margin-left: .5em; }
        .btn-copy { background: #22c55e; color: #0f172a; box-shadow: 0 4px 14px rgba(34,197,94,0.3); }
        .btn-copy:active { transform: scale(0.98); background: #16a34a; }
        .status { margin-top: 18px; font-size: 14px; font-weight: 500; min-height: 24px; line-height: 1.4; }
        .success { color: #4ade80; }
        .error { color: #f87171; }
    </style>
</head>
<body>
    <div class="card">
        <span class="badge">Шаг 2 из 2</span>
        <h2>⚡ Перехват заголовков клиента (VLESS / ядра)</h2>
        <p>Для привязки устройства к ПК выполните два простых шага:</p>
        
        <a href="/cert.pem" class="btn btn-cert" id="certBtn">📥 1. Скачать сертификат (cert.pem)</a>
        <div class="cert-hint">
            <b>iOS:</b> Настройки → Профиль загружен → Установить. Затем: Основные → Об этом устройстве → Доверие сертификатам → Включить.
        </div>

        <div class="divider">затем</div>

        <button class="btn btn-copy" id="copyBtn" type="button">📋 2. Скопировать ссылку для клиента</button>

        <div class="status" id="statusMsg"></div>
    </div>

    <script>
        const copyBtn = document.getElementById('copyBtn');
        const statusMsg = document.getElementById('statusMsg');
        const subUrl = "{{SUB_URL}}";

        copyBtn.addEventListener('click', async () => {
            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(subUrl);
                } else {
                    const el = document.createElement('textarea');
                    el.value = subUrl;
                    document.body.appendChild(el);
                    el.select();
                    document.execCommand('copy');
                    document.body.removeChild(el);
                }
                statusMsg.className = 'status success';
                statusMsg.innerHTML = '✅ <b>Ссылка скопирована!</b><br>Откройте приложение Happ → «Добавить подписку» → вставьте ссылку и обновите.';
            } catch (err) {
                statusMsg.className = 'status';
                statusMsg.innerHTML = 'Скопируйте вручную:<br><small style="word-break:break-all;color:#38bdf8;">' + subUrl + '</small>';
            }
        });
    </script>
</body>
</html>
"""

class HeaderCaptureServer:
    def __init__(self, http_port: int = 8080, https_port: int = 8443, ip: Optional[str] = None):
        self.http_port = http_port
        self.https_port = https_port
        self.ip = ip or get_best_local_ip()
        self.captured_headers = {}
        self.stop_event = threading.Event()
        self.config_store = ConfigStore()

    def create_http_handler(self):
        parent = self
        sub_url = f"https://{self.ip}:{self.https_port}/sub"
        page_html = HTML_TEMPLATE.replace("{{SUB_URL}}", sub_url)

        class HTTPHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path in ['/cert.pem', '/cert', '/ca.crt']:
                    if not CERT_FILE.exists():
                        self.send_error(404, 'Certificate not ready')
                        return
                    with open(CERT_FILE, 'rb') as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/x-x509-ca-cert')
                    self.send_header('Content-Disposition', 'attachment; filename="vpn_spoof_ca.pem"')
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(page_html.encode('utf-8'))

            def log_message(self, format, *args):
                return
        return HTTPHandler

    def create_https_interceptor_handler(self):
        parent = self
        class HTTPSInterceptorHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                headers = dict(self.headers)
                parent.captured_headers = headers
                
                hwid = headers.get('X-HWID') or headers.get('x-hwid')
                ua = headers.get('User-Agent') or headers.get('user-agent')

                print(f"\n[+] ПЕРЕХВАЧЕН ЗАПРОС ОТ КЛИЕНТА ({self.client_address[0]})")
                print(f"    User-Agent: {ua}")
                print(f"    X-HWID:     {hwid}")

                saved_headers = {}
                for k, v in headers.items():
                    if k.lower().startswith('x-') or k.lower() in ['user-agent', 'accept-language', 'accept']:
                        saved_headers[k] = v

                parent.config_store.update_headers(saved_headers)

                # Return dummy YAML so client completes successfully
                dummy_yaml = b"proxies: []\n"
                self.send_response(200)
                self.send_header('Content-Type', 'text/yaml; charset=utf-8')
                self.send_header('subscription-userinfo', 'upload=0; download=0; total=1073741824000; expire=2000000000')
                self.send_header('profile-update-interval', '24')
                self.end_headers()
                self.wfile.write(dummy_yaml)

                threading.Thread(target=parent.trigger_success).start()

            def log_message(self, format, *args):
                return
        return HTTPSInterceptorHandler

    def trigger_success(self):
        time.sleep(0.5)
        self.stop_event.set()

    def check_and_prepare_cert(self):
        all_ips = list(set(get_all_ip_addresses() + [self.ip]))
        if not CERT_FILE.exists() or not KEY_FILE.exists():
            print("[*] Генерация локального SSL-сертификата...")
            generate_self_signed_cert(CERT_FILE, KEY_FILE, all_ips)
            print("[+] Сертификат создан в data/cert.pem")
        else:
            print("[+] Локальный сертификат найден в data/cert.pem")

    def run(self):
        # 1. Check and prepare certificate
        self.check_and_prepare_cert()

        # 2. HTTP Server for web page & cert download
        httpd = http.server.HTTPServer(('0.0.0.0', self.http_port), self.create_http_handler())
        http_thread = threading.Thread(target=httpd.serve_forever)
        http_thread.daemon = True
        http_thread.start()

        # 3. HTTPS Server for capturing client headers
        httpsd = http.server.HTTPServer(('0.0.0.0', self.https_port), self.create_https_interceptor_handler())
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
        httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
        https_thread = threading.Thread(target=httpsd.serve_forever)
        https_thread.daemon = True
        https_thread.start()

        setup_url = f"http://{self.ip}:{self.http_port}/"

        print("\n" + "=" * 58)
        print(" ⚡ ШАГ 2: ПЕРЕХВАТ ЗАГОЛОВКОВ КЛИЕНТА (СЕРТИФИКАТ + HWID)")
        print("=" * 58)
        print_qr_banner("📱 ОТСКАНИРУЙТЕ QR-КОД КАМЕРОЙ ТЕЛЕФОНА", setup_url)
        print(f"[*] Откроется страница: {setup_url}")
        print("[*] На открывшейся странице:")
        print("    1. Скачайте сертификат (если еще не установлен) и включите доверие.")
        print("    2. Нажмите 'Скопировать ссылку для клиента' и добавьте подписку в клиент.")
        print("[*] Ожидаем запроса обновления подписки от клиента...\n")

        try:
            while not self.stop_event.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            print("\n[!] Перехват прерван пользователем.")
        finally:
            httpd.shutdown()
            httpsd.shutdown()
            httpd.server_close()
            httpsd.server_close()

        if self.captured_headers:
            print("\n" + "=" * 60)
            print("🎉 ЗАГОЛОВКИ КЛИЕНТА УСПЕШНО ПЕРЕХВАЧЕНЫ И СОХРАНЕНЫ!")
            print("=" * 60)
            return self.captured_headers
        return None

def main():
    capture = HeaderCaptureServer()
    headers = capture.run()
    if headers:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
