from flask import Flask, jsonify
import requests, time, hmac, hashlib, os

app = Flask(__name__)

CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
DEVICE_ID = os.environ["DEVICE_ID"]
BASE_URL = os.environ.get("BASE_URL", "https://openapi.tuyaeu.com")

def sign(msg):
    return hmac.new(CLIENT_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest().upper()

def get_token():
    t = str(int(time.time()*1000))
    s = sign(CLIENT_ID + t)
    r = requests.get(
        BASE_URL + "/v1.0/token?grant_type=1",
        headers={
            "client_id": CLIENT_ID,
            "t": t,
            "sign": s,
            "sign_method": "HMAC-SHA256"
        }
    ).json()
    return r["result"]["access_token"]

def get_status(token):
    t = str(int(time.time()*1000))
    s = sign(CLIENT_ID + token + t)
    r = requests.get(
        f"{BASE_URL}/v1.0/devices/{DEVICE_ID}/status",
        headers={
            "client_id": CLIENT_ID,
            "access_token": token,
            "t": t,
            "sign": s,
            "sign_method": "HMAC-SHA256"
        }
    ).json()
    sw = next(x for x in r["result"] if x["code"].startswith("switch"))
    return sw["value"]

@app.route("/status")
def status():
    try:
        token = get_token()
        t = str(int(time.time()*1000))
        s = sign(os.environ["CLIENT_ID"] + token + t)
        r = requests.get(
            f"{BASE_URL}/v1.0/devices/{DEVICE_ID}/status",
            headers={
                "client_id": os.environ["CLIENT_ID"],
                "access_token": token,
                "t": t,
                "sign": s,
                "sign_method": "HMAC-SHA256"
            }
        ).json()
        # On renvoie tout le JSON reçu
        return jsonify(r)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
