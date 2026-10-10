"""Paddle billing integration — webhook receiver + checkout placeholders.

STATUS: skeleton / disabled by default. The endpoint is inert until the
PADDLE_WEBHOOK_SECRET env var is set (returns 503 otherwise). Once the
Paddle seller dashboard is configured, set:
  PADDLE_WEBHOOK_SECRET  — from Paddle Dashboard > Notifications > Webhooks
  PADDLE_PRO_PRICE_ID    — Price ID for Professional $49/mo
  PADDLE_ENT_PRICE_ID    — Price ID for Enterprise $199/mo
  PADDLE_CLIENT_TOKEN    — client-side token for Paddle.js (when we wire real checkout)
Webhook URL to register in Paddle: https://pharmareg-ai.fastapicloud.dev/webhooks/paddle

Signature verification follows Paddle Billing docs (Paddle-Signature header):
  header format:  ts=<unix_ts>;h1=<hex>;h1=<hex>...   (multiple h1 = key rotation)
  signed payload: "<ts>:<raw request body bytes>"
  algorithm:      HMAC-SHA256(secret, payload).hexdigest()
  compare each h1 with hmac.compare_digest; reject stale ts (>5 min, replay protection).

User rows live in data/portal_users.json (schemaless) — paddle fields are
added lazily: "paddle_customer_id", "paddle_subscription_id". No migration needed.
"""
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
WEBHOOK_LOG = DATA_DIR / "paddle_webhooks.jsonl"
USERS_FILE = DATA_DIR / "portal_users.json"

WEBHOOK_SECRET = os.environ.get("PADDLE_WEBHOOK_SECRET", "")
PRICE_TO_PLAN = {
    os.environ.get("PADDLE_PRO_PRICE_ID", ""): "pro",
    os.environ.get("PADDLE_ENT_PRICE_ID", ""): "enterprise",
}
# drop empty keys so an unset env var can never match a real price id
PRICE_TO_PLAN = {k: v for k, v in PRICE_TO_PLAN.items() if k}

MAX_SKEW_SECONDS = 5 * 60


def _log_event(entry: dict):
    entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **entry}
    with WEBHOOK_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _verify_signature(raw_body: bytes, header: str, secret: str) -> bool:
    """Verify Paddle-Signature per Paddle Billing docs.

    header: "ts=1719934846;h1=<hex>[;h1=<hex>...]"
    signed: b"<ts>:<raw_body>"
    """
    parts = {}
    for chunk in (header or "").split(";"):
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            parts.setdefault(k.strip(), []).append(v.strip())
    ts_list = parts.get("ts", [])
    hashes = parts.get("h1", [])
    if not ts_list or not hashes:
        return False
    try:
        ts = int(ts_list[0])
    except ValueError:
        return False
    if abs(time.time() - ts) > MAX_SKEW_SECONDS:
        return False  # replay protection
    signed = f"{ts}:".encode() + raw_body
    digest = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(digest, h) for h in hashes)


def _load_users():
    if USERS_FILE.exists():
        try:
            return json.loads(USERS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_users(users):
    tmp = USERS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(users, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(USERS_FILE)


def _find_user(users, data):
    """Match a Paddle subscription event to a portal user.

    Priority: custom_data.user_id (set by our checkout) ->
              stored paddle_customer_id -> None (logged, no silent action).
    """
    custom = (data.get("custom_data") or {})
    uid = custom.get("user_id")
    if uid and uid in users:
        return users[uid]
    cust_id = data.get("customer_id")
    if cust_id:
        for u in users.values():
            if u.get("paddle_customer_id") == cust_id:
                return u
    return None


def _plan_for_event(data):
    """Map subscription items' price IDs to a portal plan (or None)."""
    for item in data.get("items", []):
        price_id = ((item.get("price") or {}).get("id")) or item.get("price_id")
        if price_id in PRICE_TO_PLAN:
            return PRICE_TO_PLAN[price_id]
    return None


@router.post("/webhooks/paddle")
async def paddle_webhook(request: Request):
    if not WEBHOOK_SECRET:
        return JSONResponse({"ok": False, "error": "webhook not configured"},
                            status_code=503)
    raw = await request.body()
    sig = request.headers.get("Paddle-Signature", "")
    if not _verify_signature(raw, sig, WEBHOOK_SECRET):
        _log_event({"event": "invalid_signature", "sig_present": bool(sig)})
        return JSONResponse({"ok": False, "error": "invalid signature"},
                            status_code=401)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse({"ok": False, "error": "bad json"}, status_code=400)

    event_type = payload.get("event_type", "")
    data = payload.get("data") or {}
    occurred = payload.get("occurred_at", "")
    _log_event({"event": event_type, "occurred_at": occurred,
                "subscription_id": data.get("id"),
                "customer_id": data.get("customer_id"),
                "status": data.get("status")})

    users = _load_users()
    user = _find_user(users, data)
    if not user:
        _log_event({"event": event_type, "note": "no matching user",
                    "customer_id": data.get("customer_id"),
                    "custom_data": data.get("custom_data")})
        # Acknowledge anyway so Paddle doesn't retry forever; owner reviews the log.
        return JSONResponse({"ok": True, "note": "no matching user"})

    result = "ignored"
    if event_type in ("subscription.created", "subscription.updated",
                      "subscription.resumed"):
        status = (data.get("status") or "").lower()
        user["paddle_customer_id"] = data.get("customer_id")
        user["paddle_subscription_id"] = data.get("id")
        if status in ("active", "trialing"):
            plan = _plan_for_event(data)
            if plan:
                user["plan"] = plan
                result = f"plan set to {plan}"
            else:
                _log_event({"event": event_type,
                            "note": "active but price id not mapped",
                            "items": data.get("items")})
                result = "active but price id unmapped"
        elif status in ("canceled", "past_due", "paused"):
            user["plan"] = "free"
            result = f"downgraded to free ({status})"
    elif event_type in ("subscription.canceled", "subscription.paused"):
        user["plan"] = "free"
        result = "downgraded to free"

    _save_users(users)
    _log_event({"event": event_type, "user_id": user.get("id"),
                "result": result})
    return JSONResponse({"ok": True, "result": result})
