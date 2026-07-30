from flask import Flask, request, jsonify
import json
import os
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time
from threading import Thread
import threading

app = Flask(__name__)

ACCOUNTS_FILE = "7otnayek.json"
TOKENS_FILE = "zebi.json"
TOKENS_CACHE_TIME = 3600

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

active_spam = {}
spam_lock = threading.Lock()

def load_accounts():
    if os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_tokens(tokens):
    data = {
        "tokens": tokens,
        "timestamp": time.time()
    }

    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)

def load_cached_tokens():
    if not os.path.exists(TOKENS_FILE):
        return None

    with open(TOKENS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    if time.time() - data.get("timestamp", 0) > TOKENS_CACHE_TIME:
        return None

    return data.get("tokens")

def get_tokens():
    tokens = load_cached_tokens()
    if tokens:
        return tokens

    accounts = load_accounts()
    tokens = []

    for uid, pwd in accounts.items():
        try:
            response = requests.get(
                f"https://saif-officiel-production.up.railway.app/token?uid={uid}&password={pwd}",
                timeout=10)

            if response.status_code == 200:
                data = response.json()

                if data.get("status") == "success":
                    token = data.get("token")

                    if token:
                        tokens.append(token)
                        print(f"تم تسجيل الدخول: {uid}")
                else:
                    print(f"فشل تسجيل الدخول: {uid}")
            else:
                print(f"HTTP {response.status_code}: {uid}")

        except Exception as e:
            print(f"خطأ {uid}: {e}")

    if tokens:
        save_tokens(tokens)
    return tokens


def encrypt_data(plain_text):
    if isinstance(plain_text, str):
        plain_text = bytes.fromhex(plain_text)

    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(plain_text, AES.block_size)).hex()


def encode_id(number):
    number = int(number)
    encoded = []

    while True:
        b = number & 0x7F
        number >>= 7

        if number:
            b |= 0x80

        encoded.append(b)

        if not number:
            break

    return bytes(encoded).hex()


def spam_worker(uid):
    tokens = get_tokens()

    if not tokens:
        print("لا توجد توكنات.")
        return

    enc_id = encode_id(uid)
    payload = f"08a7c4839f1e10{enc_id}1801"
    enc_data = encrypt_data(payload)

    while True:
        with spam_lock:
            if not active_spam.get(uid, False):
                break

        for token in tokens:
            try:
                requests.post(
                    "https://clientbp.ggpolarbear.com/RequestAddingFriend",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "X-Unity-Version": "2018.4.11f1",
                        "X-GA": "v1 1",
                        "ReleaseVersion": "OB54",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Dalvik/2.1.0",
                        "Connection": "Keep-Alive",
                        "Accept-Encoding": "gzip"
                    },
                    data=bytes.fromhex(enc_data),
                    timeout=10)
            except Exception:
                pass

        time.sleep(1)

    print(f"تم إيقاف السبام لـ {uid}")


@app.route("/spam_vip")
def start_spam():
    uid = request.args.get("uid")

    if not uid:
        return jsonify({"status": "error", "message": "أرسل uid"}), 400

    uid = int(uid)

    with spam_lock:
        if active_spam.get(uid):
            return jsonify({"status": "already_running"})

        active_spam[uid] = True

    Thread(target=spam_worker, args=(uid,), daemon=True).start()

    return jsonify({"status": "started"})


@app.route("/stop")
def stop():
    uid = request.args.get("id")

    if not uid:
        return jsonify({"status": "error"}), 400

    uid = int(uid)

    with spam_lock:
        active_spam[uid] = False

    return jsonify({"status": "stopped"})


@app.route("/")
def home():
    return jsonify({
        "status": "online"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))