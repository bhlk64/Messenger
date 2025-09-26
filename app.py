import os
import hmac
import hashlib
import requests
from flask import Flask, request, abort

app = Flask(__name__)

# Lấy secret từ ENV (Render Secrets)
PAGE_ACCESS_TOKEN = os.environ.get("PAGE_ACCESS_TOKEN")
APP_SECRET = os.environ.get("APP_SECRET")
VERIFY_TOKEN = os.environ.get("VERIFY_TOKEN", "changeme123")

if not PAGE_ACCESS_TOKEN or not APP_SECRET:
    raise RuntimeError("Thiếu PAGE_ACCESS_TOKEN hoặc APP_SECRET trong env!")

def mask(s):
    return s[:4] + "..." + s[-4:] if s else None

print("Loaded secrets:", {
    "PAGE_ACCESS_TOKEN": mask(PAGE_ACCESS_TOKEN),
    "APP_SECRET": mask(APP_SECRET),
    "VERIFY_TOKEN": VERIFY_TOKEN
})

# Xác thực chữ ký của Facebook
def verify_signature(req):
    sig = req.headers.get("X-Hub-Signature-256")
    if not sig:
        return False
    sha, signature = sig.split("=")
    if sha != "sha256":
        return False
    mac = hmac.new(APP_SECRET.encode(), msg=req.get_data(), digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature)

@app.route("/", methods=["GET"])
def home():
    return "Cheat Pro bot is running!"

@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")
        if mode == "subscribe" and token == VERIFY_TOKEN:
            return challenge, 200
        return "Verification failed", 403

    if request.method == "POST":
        if not verify_signature(request):
            abort(403)

        data = request.get_json()
        print("Webhook event:", data, flush=True)

        if "entry" in data:
            for entry in data["entry"]:
                for event in entry.get("messaging", []):
                    sender_id = event["sender"]["id"]
                    if "message" in event:
                        msg = event["message"].get("text")
                        if msg:
                            send_message(sender_id, f"Bạn vừa nói: {msg}")

        return "EVENT_RECEIVED", 200

def send_message(psid, text):
    url = "https://graph.facebook.com/v19.0/me/messages"
    params = {
        "access_token": PAGE_ACCESS_TOKEN,
        "appsecret_proof": hmac.new(
            APP_SECRET.encode(),
            msg=PAGE_ACCESS_TOKEN.encode(),
            digestmod=hashlib.sha256
        ).hexdigest()
    }
    payload = {
        "recipient": {"id": psid},
        "message": {"text": text}
    }
    r = requests.post(url, params=params, json=payload)
    if r.status_code != 200:
        print("Error sending message:", r.text)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
