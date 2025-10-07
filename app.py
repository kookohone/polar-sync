# app.py (täysi minimaali, kaikki reitit + route-listaus)
import os, json, time, pathlib, hmac, hashlib, base64, requests
from flask import Flask, request, redirect
from urllib.parse import urlencode

# --- Konfig ---
POLAR_AUTH_URL   = "https://flow.polar.com/oauth2/authorization"
POLAR_TOKEN_URL  = "https://polarremote.com/v2/oauth2/token"
ACCESSLINK       = "https://www.polaraccesslink.com/v3"

CLIENT_ID     = os.environ.get("POLAR_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("POLAR_CLIENT_SECRET", "")
REDIRECT_URI  = os.environ.get("POLAR_REDIRECT_URI", "")
WEBHOOK_URL   = os.environ.get("POLAR_WEBHOOK_PUBLIC_URL", "")

DATA_DIR = pathlib.Path(os.environ.get("DATA_DIR", "/opt/render/project/src/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
TOKENS_PATH = DATA_DIR / "polar_tokens.json"

# --- App ---
app = Flask(__name__)

def load_tokens():
    if TOKENS_PATH.exists():
        return json.loads(TOKENS_PATH.read_text())
    return {}

def save_tokens(tokens):
    TOKENS_PATH.write_text(json.dumps(tokens, indent=2, ensure_ascii=False))

def valid_signature(raw_body: bytes, signature_header: str, secret: str) -> bool:
    if not signature_header or not secret:
        return False
    dig = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).digest()
    return hmac.compare_digest(dig.hex(), signature_header.strip()) or \
           hmac.compare_digest(base64.b64encode(dig).decode("ascii"), signature_header.strip())

def save_json(obj, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2))

# --- Reitit ---
@app.route("/")
def health(): return "OK", 200

@app.route("/debug/routes")
def debug_routes():
    # listaa kaikki reitit ja sallitut metodit
    rows = []
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        rows.append(f"{rule.rule}  [{','.join(sorted(rule.methods))}] -> {rule.endpoint}")
    return "<pre>" + "\n".join(rows) + "</pre>"

@app.route("/debug/webhook-env")
def debug_webhook_env():
    tokens = load_tokens()
    return f"WEBHOOK_URL={WEBHOOK_URL or '(empty)'}<br>TOKEN_PRESENT={bool(tokens)}"

@app.route("/admin/list_data", methods=["GET"])
def admin_list_data():
    if not DATA_DIR.exists():
        return f"DATA_DIR not found: {DATA_DIR}", 200
    files = sorted([p.name for p in DATA_DIR.glob("*") if p.is_file()])
    return "<br>".join(files) or "No files yet", 200

@app.route("/admin/view/<path:fname>", methods=["GET"])
def admin_view(fname):
    p = DATA_DIR / fname
    if not p.exists():
        return "Not found", 404
    return f"<pre>{p.read_text()}</pre>", 200

def daily_transaction_pull(user_id: str, token: str):
    # 1) Aloita transaction
    r = requests.post(f"{ACCESSLINK}/users/{user_id}/exercise-transactions",
                      headers={"Authorization": f"Bearer {token}"}, timeout=30)
    if r.status_code not in (200, 201):
        app.logger.warning("start tx failed: %s %s", r.status_code, r.text)
        return f"tx start failed: {r.status_code}", 500
    tx_id = r.json().get("transaction-id")

    # 2) Listaa treenit transaktiossa
    r = requests.get(f"{ACCESSLINK}/users/{user_id}/exercise-transactions/{tx_id}",
                     headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                     timeout=30)
    if r.status_code != 200:
        return f"tx list failed: {r.status_code}", 500
    data = r.json()
    ex_urls = data.get("exercises", [])

    # 3) Nouda jokainen treeni (summary + valinnainen GPX/TCX)
    for ex_url in ex_urls:
        ex = requests.get(ex_url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
        if ex.status_code == 200:
            ex_json = ex.json()
            ex_id = ex_json.get("id") or ex_json.get("exercise-id") or "unknown"
            save_json(ex_json, DATA_DIR / f"exercise_{user_id}_{tx_id}_{ex_id}_summary.json")

            # reitit (valinnaista)
            try:
                gpx = requests.get(f"{ex_url}/gpx",
                                   headers={"Authorization": f"Bearer {token}", "Accept": "application/gpx+xml"},
                                   timeout=30)
                if gpx.status_code == 200:
                    (DATA_DIR / f"exercise_{user_id}_{tx_id}_{ex_id}.gpx").write_bytes(gpx.content)
                tcx = requests.get(f"{ex_url}/tcx",
                                   headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.garmin.tcx+xml"},
                                   timeout=30)
                if tcx.status_code == 200:
                    (DATA_DIR / f"exercise_{user_id}_{tx_id}_{ex_id}.tcx").write_bytes(tcx.content)
            except Exception as e2:
                app.logger.warning("route optional fetch failed: %s", e2)

    # 4) Kommitoi transaction
    requests.put(f"{ACCESSLINK}/users/{user_id}/exercise-transactions/{tx_id}",
                 headers={"Authorization": f"Bearer {token}"}, timeout=30)

    return f"ok, pulled {len(ex_urls)} exercises", 200


@app.route("/admin/run_daily_pull", methods=["POST"])
def run_daily_pull():
    tokens = load_tokens()
    if not tokens:
        return "no tokens; do /login", 400
    # oletetaan 1 käyttäjä
    user_id, data = next(iter(tokens.items()))
    return daily_transaction_pull(user_id, data.get("access_token", ""))


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

    resp = requests.post(
        POLAR_TOKEN_URL,
        auth=(CLIENT_ID, CLIENT_SECRET),
        headers={"Accept": "application/json;charset=UTF-8"},
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI},
        timeout=30,
    )
    if resp.status_code != 200:
        return f"Token exchange failed: {resp.status_code}<br><pre>{resp.text}</pre>", 400

    toks = resp.json()
    user_id = toks.get("x_user_id")
    if not user_id:
        return f"Missing x_user_id in token JSON.<br><pre>{toks}</pre>", 400

    tokens = load_tokens()
    tokens[str(user_id)] = {
        "access_token": toks["access_token"],
        "token_type": toks.get("token_type", "Bearer"),
        "expires_in": toks.get("expires_in"),
        "obtained_at": int(time.time()),
    }
    save_tokens(tokens)

    # Rekisteröi käyttäjä AccessLinkiin
    r = requests.post(
        f"{ACCESSLINK}/users",
        headers={"Authorization": f"Bearer {toks['access_token']}", "Accept": "application/json", "Content-Type": "application/json"},
        json={"member-id": str(user_id)},
        timeout=30,
    )
    if r.status_code not in (200, 201, 409):
        return f"/users failed: {r.status_code}<br><pre>{r.text}</pre>", 400

    return "Polar-yhdistys onnistui. Voit sulkea tämän ikkunan."

@app.route("/webhook", methods=["POST"])
def webhook():
    event = (request.headers.get("Polar-Webhook-Event") or "").upper()

    # PING läpi ilman signeerausta
    if event == "PING":
        app.logger.info("Webhook PING ok")
        return "pong", 200

    # Muut eventit vaativat signeerauksen
    secret = os.environ.get("POLAR_WEBHOOK_SECRET", "")
    if not secret:
        app.logger.warning("Webhook called for %s but POLAR_WEBHOOK_SECRET not set", event)
        return "secret not set", 401

    signature = request.headers.get("Polar-Webhook-Signature", "")
    if not valid_signature(request.get_data(), signature, secret):
        app.logger.warning("Invalid webhook signature for event %s", event)
        return "invalid signature", 401

    body = request.json or {}
    if event == "EXERCISE":
        handle_exercise_event(body)
        return "ok", 200

    return "ignored", 200

@app.route("/admin/create_webhook", methods=["POST"])
def admin_create_webhook():
    if not WEBHOOK_URL:
        return "POLAR_WEBHOOK_PUBLIC_URL is empty. Set it in Render env and redeploy.", 400
    r = requests.post(
        f"{ACCESSLINK}/webhooks",
        auth=(CLIENT_ID, CLIENT_SECRET),  # Basic Auth (client-taso)
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json={"events": ["EXERCISE"], "url": WEBHOOK_URL},
        timeout=30,
    )
    out = {"status": r.status_code, "text": r.text}
    app.logger.info("WEBHOOK CREATE RESP %s", out)
    return (json.dumps(out, ensure_ascii=False, indent=2), 200)

@app.route("/admin/activate_webhook", methods=["POST"])
def admin_activate_webhook():
    r = requests.post(f"{ACCESSLINK}/webhooks/activate", auth=(CLIENT_ID, CLIENT_SECRET), timeout=30)
    return (f"{r.status_code}\n{r.text}", r.status_code)

def handle_exercise_event(body: dict):
    try:
        user_id = str(body.get("user_id") or "")
        ex_url  = body.get("url")
        entity  = str(body.get("entity_id") or "unknown")
        if not user_id or not ex_url:
            app.logger.warning("EXERCISE event missing user_id/url: %s", body)
            return
        tokens = load_tokens()
        token  = tokens.get(user_id, {}).get("access_token")
        if not token:
            app.logger.warning("No access_token for user_id=%s (redo /login after redeploy)", user_id)
            return
        # Summary
        r = requests.get(ex_url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
        if r.status_code != 200:
            app.logger.warning("Exercise GET failed %s: %s %s", ex_url, r.status_code, r.text)
            return
        summary = r.json()
        save_json(summary, DATA_DIR / f"exercise_{user_id}_{entity}_summary.json")
        app.logger.info("Saved exercise summary for user %s entity %s", user_id, entity)
        # Optional: GPX/TCX
        try:
            gpx = requests.get(f"{ex_url}/gpx", headers={"Authorization": f"Bearer {token}", "Accept": "application/gpx+xml"}, timeout=30)
            if gpx.status_code == 200:
                (DATA_DIR / f"exercise_{user_id}_{entity}.gpx").write_bytes(gpx.content)
            tcx = requests.get(f"{ex_url}/tcx", headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.garmin.tcx+xml"}, timeout=30)
            if tcx.status_code == 200:
                (DATA_DIR / f"exercise_{user_id}_{entity}.tcx").write_bytes(tcx.content)
        except Exception as e2:
            app.logger.warning("Route download optional step failed: %s", e2)
    except Exception as e:
        app.logger.exception("handle_exercise_event exception: %s", e)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.logger.info("Starting on port %s, DATA_DIR=%s", port, DATA_DIR)
    app.run(host="0.0.0.0", port=port)
