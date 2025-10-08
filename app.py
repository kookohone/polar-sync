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

# --- Normalisoinnin apurit ---

import re, csv
from datetime import timedelta, datetime

DURATION_ISO_RE = re.compile(
    r"^P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?$"
)

def iso8601_duration_to_seconds(s: str) -> int | None:
    """Muunna ISO8601-kesto (esim. 'PT40M25S') sekunneiksi."""
    if not s or not isinstance(s, str):
        return None
    m = DURATION_ISO_RE.match(s.strip())
    if not m:
        return None
    parts = m.groupdict()
    days = int(parts.get("days") or 0)
    hours = int(parts.get("hours") or 0)
    minutes = int(parts.get("minutes") or 0)
    seconds = float(parts.get("seconds") or 0)
    td = timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
    return int(td.total_seconds())

def safe_float(x):
    try:
        return float(x)
    except Exception:
        return None

def safe_int(x):
    try:
        return int(x)
    except Exception:
        # jos float voidaan konvertoida järkevästi
        try:
            return int(float(x))
        except Exception:
            return None

def format_hms(total_seconds: int | None) -> str:
    if total_seconds is None:
        return ""
    m, s = divmod(int(total_seconds), 60)
    h, m = divmod(m, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:d}:{s:02d}"

def pace_from_speed_mps(speed_mps: float | None) -> str:
    """Muunna m/s → min/km muodossa M:SS."""
    if not speed_mps or speed_mps <= 0:
        return ""
    sec_per_km = 1000.0 / speed_mps
    m, s = divmod(int(round(sec_per_km)), 60)
    return f"{m}:{s:02d}"

def norm_summary_row(js: dict) -> dict:
    """
    Normalisoi Polar exercise summary yhdeksi CSV-riviksi.
    Tukee sekä 'snake' että 'kebab' -avaimia varalta.
    """
    get = lambda *keys, default=None: next(
        (js.get(k) for k in keys if k in js), default
    )

    ex_id = get("id", "exercise-id", default="")
    sport = get("sport", default="")
    # start time
    start = get("start_time", "start-time", "start", default="")
    # duration – voi olla sekunteina tai ISO8601-stringinä
    duration_field = get("duration", default=None)
    duration_seconds = None
    if isinstance(duration_field, dict):
        duration_seconds = safe_int(duration_field.get("total"))
    elif isinstance(duration_field, (int, float, str)):
        if isinstance(duration_field, (int, float)):
            duration_seconds = int(duration_field)
        else:
            # koita ISO8601
            duration_seconds = iso8601_duration_to_seconds(duration_field)
    duration_hms = format_hms(duration_seconds)

    # distance
    dist_field = get("distance", default=None)
    if isinstance(dist_field, dict):
        dist_m = safe_float(dist_field.get("total") or dist_field.get("value"))
    else:
        dist_m = safe_float(dist_field)
    distance_km = round(dist_m / 1000.0, 3) if dist_m else None

    # heart rate
    hr = get("heart_rate", "heart-rate", default={}) or {}
    hr_avg = safe_int(hr.get("average"))
    hr_max = safe_int(hr.get("maximum") or hr.get("max"))

    # speed & power
    spd = get("speed", default={}) or {}
    speed_avg_mps = safe_float(spd.get("average"))
    pace_avg = pace_from_speed_mps(speed_avg_mps)
    pwr = get("power", default={}) or {}
    power_avg = safe_float(pwr.get("average"))

    kcal = safe_float(get("calories", "energy"))

    # lisä: nopeus km/h
    speed_kmh = round(speed_avg_mps * 3.6, 2) if speed_avg_mps else None

    return {
        "exercise_id": ex_id,
        "start_time": start,
        "sport": sport,
        "duration": duration_hms,
        "duration_seconds": duration_seconds if duration_seconds is not None else "",
        "distance_km": distance_km if distance_km is not None else "",
        "hr_avg": hr_avg if hr_avg is not None else "",
        "hr_max": hr_max if hr_max is not None else "",
        "speed_avg_mps": round(speed_avg_mps, 3) if speed_avg_mps else "",
        "speed_avg_kmh": speed_kmh if speed_kmh is not None else "",
        "pace_avg": pace_avg,
        "power_avg": round(power_avg, 1) if power_avg else "",
        "kcal": round(kcal, 0) if kcal else "",
    }

MASTER_CSV_PATH = DATA_DIR / "master.csv"
MASTER_FIELDS = [
    "exercise_id","start_time","sport",
    "duration","duration_seconds",
    "distance_km",
    "hr_avg","hr_max",
    "speed_avg_mps","speed_avg_kmh","pace_avg",
    "power_avg","kcal"
]

def append_master_row(row: dict):
    """Kirjoita rivi master.csv:ään; lisää header jos ei vielä ole."""
    write_header = not MASTER_CSV_PATH.exists()
    with MASTER_CSV_PATH.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=MASTER_FIELDS)
        if write_header:
            w.writeheader()
        # varmista, että kaikki kentät on rivissä
        out = {k: row.get(k, "") for k in MASTER_FIELDS}
        w.writerow(out)

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

@app.route("/debug/last_webhook", methods=["GET"])
def debug_last_webhook():
    p = DATA_DIR / "last_webhook.json"
    if not p.exists():
        return "no webhook yet", 200
    return f"<pre>{p.read_text()}</pre>", 200

@app.route("/admin/list_data", methods=["GET"])
def admin_list_data():
    if not DATA_DIR.exists():
        return f"DATA_DIR not found: {DATA_DIR}", 200
    files = sorted([p.name for p in DATA_DIR.glob("*") if p.is_file()])
    return "<br>".join(files) or "No files yet", 200

@app.route("/admin/fetch_last", methods=["POST"])
def admin_fetch_last():
    p = DATA_DIR / "last_webhook.json"
    if not p.exists():
        return "no last_webhook.json; do a workout / wait for webhook", 400
    try:
        last = json.loads(p.read_text())
        event = (last.get("event") or "").upper()
        body  = last.get("body") or {}
        if event != "EXERCISE":
            return f"last event is {event}, not EXERCISE", 400
        handle_exercise_event(body)  # käyttää samaa logiikkaa kuin webhook
        return "fetched", 200
    except Exception as e:
        app.logger.exception("admin_fetch_last error")
        return f"fetch_last error: {e}", 500

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

            # >>> UUSI: normalisoitu rivi masteriin
            try:
                row = norm_summary_row(ex_json)
                append_master_row(row)
                app.logger.info("Appended master.csv for exercise %s", row.get("exercise_id",""))
            except Exception as e:
                app.logger.warning("Failed to append master row: %s", e)
            # <<<

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

import csv
from datetime import datetime

def _parse_float(x):
    try:
        return float(x)
    except Exception:
        return None

def _parse_int(x):
    try:
        return int(x)
    except Exception:
        return None

def _parse_iso(ts):
    # koita parsea muutamaa muotoa, palauta ISO YYYY-MM-DD HH:MM:SS
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    return ts or ""

def _row_from_summary(js):
    """
    Yritetään tukea Polarin summary-rakenteita joustavasti.
    Täydennä myöhemmin kenttiä sen mukaan mitä datassasi on.
    """
    # tyypillisiä avaimia:
    # id / exercise-id, start_time, duration, distance, sport, calories,
    # heart_rate: {average, maximum}, speed: {average, max}, power: {average, max}
    ex_id = js.get("id") or js.get("exercise-id") or ""
    sport = js.get("sport", "")
    start = _parse_iso(js.get("start_time") or js.get("start-time") or js.get("start"))
    # kesto sekunteina -> min:ss
    duration_s = _parse_int(js.get("duration", {}).get("total") if isinstance(js.get("duration"), dict) else js.get("duration"))
    if duration_s is None:
        # joskus duration voi olla ISO8601 "PT0H35M10S" -> jätetään stringiksi
        duration_fmt = js.get("duration") if isinstance(js.get("duration"), str) else ""
    else:
        m, s = divmod(duration_s, 60)
        h, m = divmod(m, 60)
        duration_fmt = f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:d}:{s:02d}"

    distance_m = js.get("distance", {})
    if isinstance(distance_m, dict):
        dist_m = _parse_float(distance_m.get("total") or distance_m.get("value"))
    else:
        dist_m = _parse_float(distance_m)

    hr = js.get("heart_rate") or js.get("heart-rate") or {}
    hr_avg = _parse_int(hr.get("average"))
    hr_max = _parse_int(hr.get("maximum") or hr.get("max"))

    spd = js.get("speed") or {}
    spd_avg = _parse_float(spd.get("average"))  # m/s
    pace_avg = None
    if spd_avg and spd_avg > 0:
        pace_sec_per_km = 1000.0 / spd_avg
        pace_m, pace_s = divmod(int(round(pace_sec_per_km)), 60)
        pace_avg = f"{pace_m}:{pace_s:02d}"

    pwr = js.get("power") or {}
    pwr_avg = _parse_float(pwr.get("average"))
    kcal = _parse_float(js.get("calories") or js.get("energy"))

    return {
        "exercise_id": ex_id,
        "start_time": start,
        "sport": sport,
        "duration": duration_fmt,
        "duration_seconds": duration_s or "",
        "distance_m": dist_m or "",
        "distance_km": round(dist_m/1000.0, 3) if dist_m else "",
        "hr_avg": hr_avg or "",
        "hr_max": hr_max or "",
        "speed_avg_mps": round(spd_avg, 3) if spd_avg else "",
        "pace_avg": pace_avg or "",
        "power_avg": round(pwr_avg, 1) if pwr_avg else "",
        "kcal": round(kcal, 0) if kcal else "",
    }

@app.route("/admin/build_master", methods=["POST"])
def build_master():
    # kerää kaikki *_summary.json-tiedostot
    summaries = sorted([p for p in DATA_DIR.glob("exercise_*_summary.json") if p.is_file()])
    if not summaries:
        return "No summaries found. Trigger a workout or run /admin/run_daily_pull first.", 400

    rows = []
    for p in summaries:
        try:
            js = json.loads(p.read_text())
            rows.append(_row_from_summary(js))
        except Exception as e:
            app.logger.warning("parse failed for %s: %s", p.name, e)

    if not rows:
        return "No parsable summaries.", 400

    # CSV
    csv_path = DATA_DIR / "master.csv"
    fieldnames = list(rows[0].keys())
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    # (valinnainen) Parquet, jos pyarrow asennettu requirementsiin
    pq_path = DATA_DIR / "master.parquet"
    try:
        import pandas as pd
        df = pd.DataFrame(rows)
        df.to_parquet(pq_path, index=False)
        made_pq = True
    except Exception as e:
        app.logger.info("Parquet not written (%s). CSV is available.", e)
        made_pq = False

    msg = f"Built master.csv ({len(rows)} rows)" + (", master.parquet" if made_pq else "")
    return msg, 200

@app.route("/admin/download/<path:fname>", methods=["GET"])
def download_file(fname):
    p = DATA_DIR / fname
    if not p.exists():
        return "Not found", 404
    # kevyt tiedostonpalautus
    from flask import send_file
    return send_file(str(p), as_attachment=True)

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

    # PING läpi
    if event == "PING":
        app.logger.info("Webhook PING ok")
        (DATA_DIR / "last_webhook.json").write_text(json.dumps({"event":"PING"}, indent=2))
        return "pong", 200

    # muut eventit vaativat signeerauksen
    secret = os.environ.get("POLAR_WEBHOOK_SECRET", "")
    if not secret:
        return "secret not set", 401

    signature = request.headers.get("Polar-Webhook-Signature", "")
    raw = request.get_data()
    if not valid_signature(raw, signature, secret):
        return "invalid signature", 401

    body = request.json or {}
    # talleta viimeisin webhook debugiin
    save_json({"event": event, "body": body}, DATA_DIR / "last_webhook.json")

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
        
                # >>> UUSI: normalisoitu rivi masteriin
        try:
            row = norm_summary_row(summary)
            append_master_row(row)
            app.logger.info("Appended master.csv for exercise %s", row.get("exercise_id",""))
        except Exception as e:
            app.logger.warning("Failed to append master row: %s", e)
        # <<<
        
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
