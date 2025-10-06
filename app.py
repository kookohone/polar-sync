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

import hmac, hashlib, base64  # varmista että nämä on importattu

def valid_signature(raw_body: bytes, signature_header: str, secret: str) -> bool:
    """
    Tarkistaa Polarin webhook-allekirjoituksen.
    Polar lähettää HMAC-SHA256:lla lasketun allekirjoituksen headerissa:
      Polar-Webhook-Signature: <hex tai base64>
    Lasketaan sekä hex- että base64-muoto ja hyväksytään, jos jompikumpi täsmää.
    """
    if not signature_header or not secret:
        return False
    # HMAC digest
    digest_bytes = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).digest()
    computed_hex = digest_bytes.hex()
    computed_b64 = base64.b64encode(digest_bytes).decode("ascii")

    sig = signature_header.strip()
    return hmac.compare_digest(computed_hex, sig) or hmac.compare_digest(computed_b64, sig)

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
            return f"Token exchange failed: {resp.status_code}<br><pre>{resp.text}</pre>", 400

        toks = resp.json()
        user_id = toks.get("x_user_id")  # <-- NYT OIKEIN: JSONISTA
        if not user_id:
            return f"Missing x_user_id in token JSON.<br><pre>{toks}</pre>", 400

        # Tallenna token
        tokens = load_tokens()
        tokens[str(user_id)] = {
            "access_token": toks["access_token"],
            "token_type": toks.get("token_type", "Bearer"),
            "expires_in": toks.get("expires_in"),
            "obtained_at": int(time.time()),
        }
        save_tokens(tokens)

        # Rekisteröi käyttäjä AccessLinkiin (JSON body + oikea content-type)
        register_headers = {
            "Authorization": f"Bearer {toks['access_token']}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        register_body = {"member-id": str(user_id)}
        r = requests.post(f"{ACCESSLINK}/users", headers=register_headers, json=register_body, timeout=30)

        if r.status_code not in (200, 201, 409):
            return f"/users failed: {r.status_code}<br><pre>{r.text}</pre>", 400

        return "Polar-yhdistys onnistui. Voit sulkea tämän ikkunan."

    except Exception as e:
        app.logger.exception("Callback exception")
        return f"Callback exception: {e}", 500


@app.route("/webhook", methods=["POST"])
def webhook():
    event = (request.headers.get("Polar-Webhook-Event") or "").upper()

    # 1) Salli PING ilman allekirjoitusta, jotta webhookin luonti onnistuu
    if event == "PING":
        app.logger.info("Webhook PING ok")
        return "pong", 200

    # 2) Muut eventit (EXERCISE ym.) vaativat allekirjoituksen, jos secret on asetettu
    secret = os.environ.get("POLAR_WEBHOOK_SECRET", "")
    if not secret:
        app.logger.warning("Webhook called for %s but POLAR_WEBHOOK_SECRET not set", event)
        # Setup-vaiheessa voidaan palauttaa 401 (ei hyväksytä EXERCISEä ennen kuin secret on asetettu)
        return "secret not set", 401

    signature = request.headers.get("Polar-Webhook-Signature", "")
    if not valid_signature(request.get_data(), signature, secret):
        app.logger.warning("Invalid webhook signature for event %s", event)
        return "invalid signature", 401

    body = request.json or {}

    if event == "EXERCISE":
        handle_exercise_event(body)
        return "ok", 200

    # Lisää tähän muut eventit tarvittaessa (ACTIVITY_SUMMARY, SLEEP, CHR...)
    return "ignored", 200

# --- ADMIN: webhookin luonti/aktivointi & daily pull hookit ---

@app.route("/admin/create_webhook", methods=["POST"])
def admin_create_webhook():
    if not WEBHOOK_URL:
        return "POLAR_WEBHOOK_PUBLIC_URL is empty. Set it in Render env and redeploy.", 400

    try:
        r = requests.post(
            f"{ACCESSLINK}/webhooks",
            auth=(CLIENT_ID, CLIENT_SECRET),  # <-- Basic Auth, EI Bearer
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={
                "events": ["EXERCISE"],  # voit lisätä myöhemmin ACTIVITY, SLEEP, CHR...
                "url": WEBHOOK_URL,
            },
            timeout=30,
        )

        out = {
            "status": r.status_code,
            "text": r.text,
            "note": "If status is 201, copy signature_secret_key and set POLAR_WEBHOOK_SECRET env, then redeploy. If 409, webhook already exists."
        }
        app.logger.info("WEBHOOK CREATE RESP %s", out)
        return (json.dumps(out, ensure_ascii=False, indent=2), 200)

    except Exception as e:
        app.logger.exception("create_webhook exception")
        return f"create_webhook exception: {e}", 500


@app.route("/admin/activate_webhook", methods=["POST"])
def admin_activate_webhook():
    try:
        r = requests.post(
            f"{ACCESSLINK}/webhooks/activate",
            auth=(CLIENT_ID, CLIENT_SECRET),  # <-- Basic Auth
            timeout=30
        )
        return (f"{r.status_code}\n{r.text}", r.status_code)
    except Exception as e:
        app.logger.exception("activate_webhook exception")
        return f"activate_webhook exception: {e}", 500

# 3) KÄYNNISTYS: käytä Renderin PORT-ympäristömuuttujaa
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
