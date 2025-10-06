# app.py
import os, hmac, hashlib, json, time, pathlib, requests
from flask import Flask, request, redirect
from urllib.parse import urlencode

POLAR_AUTH_URL = "https://flow.polar.com/oauth2/authorization"
POLAR_TOKEN_URL = "https://polarremote.com/v2/oauth2/token"
ACCESSLINK = "https://www.polaraccesslink.com/v3"

CLIENT_ID = os.environ.get("POLAR_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("POLAR_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("POLAR_REDIRECT_URI", "")
WEBHOOK_URL = os.environ.get("POLAR_WEBHOOK_PUBLIC_URL", "")
DATA_DIR = pathlib.Path(os.environ.get("DATA_DIR", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# 1) LUO APP ENSIN
app = Flask(__name__)

TOKENS_PATH = DATA_DIR / "polar_tokens.json"

def load_tokens():
    if TOKENS_PATH.exists():
        return json.loads(TOKENS_PATH.read_text())
    return {}

def save_tokens(tokens):
    TOKENS_PATH.write_text(json.dumps(tokens, indent=2, ensure_ascii=False))

def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}

# 2) REITIT VASTA TÄMÄN JÄLKEEN

@app.route("/")
def health():
    return "OK", 200

@app.route("/login")
def login():
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "scope": "accesslink.read_all",
        "redirect_uri": REDIRECT_URI
    }
    return redirect(f"{POLAR_AUTH_URL}?{urlencode(params)}")

@app.route("/oauth2/callback")
def oauth_cb():
    code = request.args.get("code")
    if not code:
        return "Missing ?code in callback", 400

    try:
        # 1) Vaihda authorization code -> access token
        resp = requests.post(
            POLAR_TOKEN_URL,
            auth=(CLIENT_ID, CLIENT_SECRET),
            headers={"Accept": "application/json;charset=UTF-8"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
            timeout=30,
        )

        if resp.status_code != 200:
            return (
                f"Token exchange failed: {resp.status_code}"
                f"<br><pre>{resp.text}</pre>",
                400,
            )

        toks = resp.json()
        user_id = resp.headers.get("x_user_id")
        if not user_id:
            return (
                "Missing x_user_id header from Polar token response."
                f"<br><pre>{dict(resp.headers)}</pre>",
                400,
            )

        # 2) Tallenna token
        tokens = load_tokens()
        tokens[str(user_id)] = {
            "access_token": toks["access_token"],
            "token_type": toks.get("token_type", "Bearer"),
            "expires_in": toks.get("expires_in"),
            "obtained_at": int(time.time()),
        }
        save_tokens(tokens)

        # 3) Rekisteröi käyttäjä AccessLinkiin (JSON-body + oikea Content-Type)
        register_headers = {
            "Authorization": f"Bearer {toks['access_token']}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        register_body = {"member-id": str(user_id)}
        r = requests.post(
            f"{ACCESSLINK}/users",
            headers=register_headers,
            json=register_body,
            timeout=30,
        )

        # Salli 200 (OK), 201 (Created) ja 409 (Already registered)
        if r.status_code not in (200, 201, 409):
            return (
                f"/users failed: {r.status_code}"
                f"<br><pre>{r.text}</pre>",
                400,
            )

        return "Polar-yhdistys onnistui. Voit sulkea tämän ikkunan."

    except Exception as e:
        app.logger.exception("Callback exception")
        return f"Callback exception: {e}", 500


@app.route("/webhook", methods=["POST"])
def webhook():
    secret = os.environ.get("POLAR_WEBHOOK_SECRET", "")
    if not secret:
        return "missing secret", 500
    signature = request.headers.get("Polar-Webhook-Signature", "")
    if not valid_signature(request.get_data(), signature, secret):
        return "invalid signature", 401

    event = request.headers.get("Polar-Webhook-Event")
    body = request.json or {}
    if event == "PING":
        return "pong", 200
    if event == "EXERCISE":
        handle_exercise_event(body)
    return "ok", 200

def handle_exercise_event(body):
    user_id = str(body.get("user_id"))
    url = body.get("url")
    tokens = load_tokens()
    token = tokens.get(user_id, {}).get("access_token")
    if not token or not url:
        return
    r = requests.get(url, headers=auth_headers(token), timeout=30)
    if r.status_code == 200:
        summary = r.json()
        (DATA_DIR / f"exercise_{user_id}_{body.get('entity_id')}_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2)
        )

# --- ADMIN: webhookin luonti/aktivointi & daily pull hookit ---

@app.route("/admin/create_webhook", methods=["POST"])
def admin_create_webhook():
    tokens = load_tokens()
    if not tokens:
        return "no tokens", 400
    user_id, data = next(iter(tokens.items()))
    token = data["access_token"]
    r = requests.post(
        f"{ACCESSLINK}/webhooks",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        json={"events": ["EXERCISE"], "url": WEBHOOK_URL},
        timeout=30
    )
    r.raise_for_status()
    info = r.json()
    app.logger.info("WEBHOOK CREATED: %s", info)
    return info, 200

@app.route("/admin/activate_webhook", methods=["POST"])
def admin_activate_webhook():
    tokens = load_tokens()
    if not tokens:
        return "no tokens", 400
    user_id, data = next(iter(tokens.items()))
    token = data["access_token"]
    r = requests.post(f"{ACCESSLINK}/webhooks/activate",
                      headers={"Authorization": f"Bearer {token}"}, timeout=30)
    return (r.text, r.status_code)

# 3) KÄYNNISTYS: käytä Renderin PORT-ympäristömuuttujaa
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
