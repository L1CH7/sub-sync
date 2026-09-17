import http.server
import json
import threading
import time
import sys
import os
from .net_utils import get_best_local_ip, get_all_ip_addresses
from .qr_utils import print_qr_banner, render_solid_terminal_qr

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>VPN Spoof - Шаг 1: Ссылка подписки</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
        .card { background: #1e293b; border-radius: 20px; padding: 26px; max-width: 440px; width: 100%; box-shadow: 0 16px 36px rgba(0,0,0,0.6); text-align: center; border: 1px solid #334155; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; background: #0284c7; color: #f0f9ff; margin-bottom: 12px; text-transform: uppercase; }
        h2 { font-size: 22px; margin-bottom: 8px; color: #38bdf8; }
        p { font-size: 14px; color: #94a3b8; margin-bottom: 22px; line-height: 1.5; }
        .btn { display: flex; align-items: center; justify-content: center; gap: 8px; width: 100%; padding: 16px; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.2s; text-decoration: none; }
        .btn-paste { background: #38bdf8; color: #0f172a; margin-bottom: 14px; box-shadow: 0 4px 14px rgba(56,189,248,0.3); }
        .btn-paste:active { transform: scale(0.98); background: #0ea5e9; }
        .divider { display: flex; align-items: center; text-align: center; color: #64748b; font-size: 12px; margin: 14px 0; }
        .divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid #334155; }
        .divider:not(:empty)::before { margin-right: .5em; }
        .divider:not(:empty)::after { margin-left: .5em; }
        .input-box { width: 100%; padding: 14px; border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: #f8fafc; font-size: 14px; margin-bottom: 12px; outline: none; }
        .input-box:focus { border-color: #38bdf8; }
        .btn-send { background: #22c55e; color: #0f172a; }
        .btn-send:active { transform: scale(0.98); }
        .status { margin-top: 18px; font-size: 14px; font-weight: 500; min-height: 24px; line-height: 1.4; }
        .success { color: #4ade80; }
        .error { color: #f87171; }
    </style>
</head>
<body>
    <div class="card">
        <span class="badge">Шаг 1 из 2</span>
        <h2>⚡ Передача ссылки на ПК</h2>
        <p>Нажмите кнопку, чтобы вставить скопированную ссылку из буфера обмена:</p>
        
        <button class="btn btn-paste" id="pasteBtn" type="button">📋 Вставить из буфера и отправить</button>
        
        <div class="divider">или вручную</div>

        <input type="text" class="input-box" id="urlInput" placeholder="Удерживайте палец и нажмите «Вставить»...">
        <button class="btn btn-send" id="sendBtn" type="button">Отправить на ПК</button>

        <div class="status" id="statusMsg"></div>
    </div>

    <script>
        const pasteBtn = document.getElementById('pasteBtn');
        const sendBtn = document.getElementById('sendBtn');
        const urlInput = document.getElementById('urlInput');
        const statusMsg = document.getElementById('statusMsg');

        async function sendUrl(rawUrl) {
            const url = (rawUrl || '').trim();
            if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
                statusMsg.className = 'status error';
                statusMsg.textContent = '❌ Вставьте корректную ссылку (начинается с http/https)';
                return;
            }
            statusMsg.className = 'status';
            statusMsg.textContent = '⏳ Передаем на ПК...';
            try {
                const res = await fetch('/api/submit', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                const data = await res.json();
                if (data.status === 'ok') {
                    statusMsg.className = 'status success';
                    statusMsg.innerHTML = '✅ <b>Успешно отправлено!</b><br>ПК принял ссылку. Переходите к Шагу 2.';
                    pasteBtn.style.display = 'none';
                    sendBtn.style.display = 'none';
                    urlInput.style.display = 'none';
                    document.querySelector('.divider').style.display = 'none';
                } else {
                    throw new Error('Server returned error');
                }
            } catch (err) {
                statusMsg.className = 'status error';
                statusMsg.textContent = '❌ Ошибка соединения с ПК';
            }
        }

        pasteBtn.addEventListener('click', async () => {
            try {
                if (navigator.clipboard && navigator.clipboard.readText) {
                    const text = await navigator.clipboard.readText();
                    if (text && text.trim().startsWith('http')) {
                        urlInput.value = text.trim();
                        await sendUrl(text.trim());
                        return;
                    }
                }
            } catch (e) {
                console.log('Clipboard read blocked:', e);
            }
            // Fallback if browser requires manual paste
            statusMsg.className = 'status error';
            statusMsg.textContent = '👉 Удерживайте палец в поле ниже и выберите «Вставить»';
            urlInput.focus();
        });

        sendBtn.addEventListener('click', () => {
            sendUrl(urlInput.value);
        });

        urlInput.addEventListener('input', () => {
            if (urlInput.value.startsWith('http://') || urlInput.value.startsWith('https://')) {
                sendUrl(urlInput.value);
            }
        });
    </script>
</body>
</html>
"""

class LinkReceiverServer:
    def __init__(self, port=8080, ip=None):
        self.port = port
        self.ip = ip or get_best_local_ip()
        self.received_url = None
        self.server = None
        self.stop_event = threading.Event()

    def create_handler(self):
        parent = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(HTML_TEMPLATE.encode('utf-8'))

            def do_POST(self):
                if self.path == '/api/submit':
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length)
                    try:
                        data = json.loads(body.decode('utf-8'))
                        url = data.get('url')
                        if url:
                            parent.received_url = url
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.end_headers()
                            self.wfile.write(b'{"status":"ok"}')
                            
                            threading.Thread(target=self.delayed_shutdown).start()
                            return
                    except Exception:
                        pass
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"status":"error"}')

            def delayed_shutdown(self):
                time.sleep(0.3)
                parent.stop_event.set()

            def log_message(self, format, *args):
                return
        return Handler

    def run(self):
        handler = self.create_handler()
        self.server = http.server.HTTPServer(('0.0.0.0', self.port), handler)
        
        qr_url = f"http://{self.ip}:{self.port}/"
        print_qr_banner("📱 ШАГ 1: ОТСКАНИРУЙТЕ QR ДЛЯ ПЕРЕДАЧИ ССЫЛКИ", qr_url)
        print(f"[*] Сервер ожидает подключения: {qr_url}")
        print("[*] На телефоне нажмите 'Вставить из буфера'...\n")

        server_thread = threading.Thread(target=self.server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        try:
            while not self.stop_event.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            print("\n[!] Остановлено пользователем.")
        finally:
            self.server.shutdown()
            self.server.server_close()

        if self.received_url:
            print("\n" + "=" * 60)
            print("🎉 УСПЕШНО ПОЛУЧЕН АДРЕС ПОДПИСКИ:")
            print(f"   {self.received_url}")
            print("=" * 60)
        return self.received_url

def main():
    receiver = LinkReceiverServer(port=8080)
    url = receiver.run()
    if url:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
