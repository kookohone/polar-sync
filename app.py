# --- ADMIN: luo/aktivoi webhook ---
@app.route("/admin/create_webhook", methods=["POST"])
def admin_create_webhook():
    tokens = load_tokens()
    # Oletus: käytössä vain yksi käyttäjä (sinä). Ota ensimmäinen token.
    if not tokens:
        return "no tokens", 400
    user_id, data = next(iter(tokens.items()))
    token = data["access_token"]
    # Luo webhook
    r = requests.post(
        f"{ACCESSLINK}/webhooks",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        json={"events": ["EXERCISE"], "url": os.environ["POLAR_WEBHOOK_PUBLIC_URL"]},
        timeout=30
    )
    r.raise_for_status()
    info = r.json()
    # Tästä saat signature_secret_key:n – tulosta lokiin luettavaksi Render-logeista
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
