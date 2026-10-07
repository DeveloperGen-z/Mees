"""Real Meesho API client — OTPLESS login flow + FOD (first-order discount).

Flow (reverse-engineered from Fiddler captures + decoded APK):
  1. GET  https://user-auth.otpless.app/v2/state?...
     -> {"state": "<uuid>"}
  2. POST https://user-auth.otpless.app/v3/lp/user/transaction/intent/{state}
     -> quantumLeap { uid, channelAuthToken, asId }
     (OTP is delivered via WhatsApp/SMS by OTPLESS)
  3. POST https://user-auth.otpless.app/v3/lp/user/transaction/otp/{state}
     -> oneTap.token + oneTap.merchantUserInfo.idToken (RS256 JWT from OTPLESS)
  4. POST https://prod.meeshoapi.com/api/2.0/user/login
     body: {
       login_type: "otpless",
       otpless: {
         token,                       # oneTap.token
         id_token,                    # base64(iv12 || AES-128-GCM(idToken, key))   (m8/w;->A)
         aes_key_encrypted,           # base64(RSA/ECB/PKCS1PADDING(key))           (i70/b;->a)
         version: "v2"
       },
       ga_id
     }
     -> { user: { user_id, phone }, xoox: { xo: "<logged-in JWT>" } }
"""
import base64
import json
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
import random
import secrets
import time
import uuid

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------- constants
MEESHO_API = "https://prod.meeshoapi.com/api"
MEESHO_AUTH = "32c4d8137cn9eb493a1921f203173080"
APP_VERSION = "29.1"
APP_VERSION_CODE = "860"
APPLICATION_ID = "com.meesho.supply"

# Anonymous xo captured from the app (valid until ~2031). Anonymous user id
# is random per install, so reusing it is safe for a server-side bot.
ANON_XO = ("eyJ0eXBlIjoiY29tcG9zaXRlIn0=.eyJqd3QiOiJleUpoYkdjaU9pSklVekkxTmlJc0ltaDBkSEJ6"
           "T2k4dmJXVmxjMmh2TG1OdmJTOXBjMjlmWTI5MWJuUnllVjlqYjJSbElqb2lTVTRpTENKb2RIUndjem92"
           "TDIxbFpYTm9ieTVqYjIwdmRtVnljMmx2YmlJNklqRWlMQ0owZVhBaU9pSktWMVFpZlEuZXlKbGVIQWlP"
           "akU1TkRVek16STVOemdzSW1oMGRIQnpPaTh2YldWbGMyaHZMbU52YlM5aGJtOXVlVzF2ZFhOZmRYTmxj"
           "bDlwWkNJNkltTTVZbUk0WVRVekxUSXhaVE10TkRkallTMWlOamMwTFdGalpURXpOekZtWVRVM01TSXNJ"
           "bWgwZEhCek9pOHZiV1ZsYzJodkxtTnZiUzlwYm5OMFlXNWpaVjlwWkNJNkltUTNNVGc1TW1OaFlUZ3la"
           "alE1TlRFNVpqUmhNek5oTUdVd1lqZzNaamN3SWl3aWFXRjBJam94TnpnM05qVXlPVGM0ZlEuLUN6TXkt"
           "TEJ2VHpGV042VlROMDNKdzItLXhiX0lqSU9VZmpJRTk4eWlQUSIsInhvIjoiIn0=")

# Meesho public key (SPKI DER, base64) extracted from decoded APK (i70/b;->a)
MEESHO_RSA_PUBKEY_B64 = ("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAslmrLKGRzVnAtii3o89yI33FXZoRfBJ"
                         "V89PaCTp9Mxu7FgAaAOtaOnB2xWGG2a6Rz6zRzKPilRdAsm5oBW8mm8Uzvt7mbf7c7pjfBrjNdnKji"
                         "/9/zM3fpjh364/GwG3OpyYngD49i09ySljA7Elh97Pp+QJH2z25Xv2eRSHJPizgQ8TE1bJkP9fd9J"
                         "cfpGFyeEJX1bUIbgRlfED2TpJKGeaEfZ9no5+i/rgCaIRO9t86UqgeVJyCyJLnUkrU/ARPj9q/Aij"
                         "JV9kvyPT137UQLO+Cl6nZYOglqGcPnRbGiW6WM7imkSxR2XBn6N4ojf49nJOwnN826hkdH5JaPJ1p"
                         "AQIDAQAB")

# Real anonymous xos captured from the app + files found in XO_STORE_DIR. Each
# root identity maps to a server-side FOD bucket (they also drift over time, e.g.
# x0 went 75 -> 90), so rotating per roll returns a real, different offer each
# tap. Binding a fresh account mints a new anonymous identity -> save it here.
XO_STORE_DIR = "/data/data/com.termux/files/home/.cache/opencode/tmp/xos"
ANON_XO_POOL = []


def _load_anon_xo_pool() -> list:
    """Load every real anonymous xo from XO_STORE_DIR (one per line). Each file
    holds one captured composite xo. Dedup by the anonymous_user_id claim; return
    a list of (user_id, xo) so callers can rotate for a different live offer."""
    out = []
    try:
        for name in sorted(os.listdir(XO_STORE_DIR)):
            if not name.endswith(".txt"):
                continue
            p = os.path.join(XO_STORE_DIR, name)
            xo = open(p).read().strip()
            if not xo or len(xo) < 100:
                continue
            try:
                u = (_api_xo_user_id(xo) or name)
            except Exception:
                u = name
            if name.startswith("x1_") or u == "c39c37ce":
                continue
            if u not in [u0 for u0, _ in out]:
                out.append((u, xo))
    except Exception:
        pass
    if not out:
        out = [("c9bb8a53", ANON_XO)]
    return out


_ANON_XO_POOL_CACHE = {"ts": 0.0, "pool": []}


def anon_xo_pool(force_refresh: bool = False) -> list:
    """Rotating-safe pool of real anonymous xos. Refreshed from disk each minute
    so a newly bound account (which mints a fresh identity) joins automatically."""
    now = time.time()
    if force_refresh or (now - _ANON_XO_POOL_CACHE["ts"]) > 60:
        _ANON_XO_POOL_CACHE["pool"] = _load_anon_xo_pool()
        _ANON_XO_POOL_CACHE["ts"] = now
    return _ANON_XO_POOL_CACHE["pool"]


def _api_xo_user_id(xo: str) -> str:
    """Best-effort anonymous_user_id from a composite xo (returns '' if unparsable)."""
    try:
        inner = json.loads(_b64url_decode(xo.split(".")[1]))
        jwt = inner.get("jwt", "")
        payload = json.loads(_b64url_decode(jwt.split(".")[1]))
        return str(payload.get("https://meesho.com/anonymous_user_id", ""))
    except Exception:
        return ""

# ----------------------------------------------------------- OTPLESS config
OTPLESS_APP_ID = "XN07RN1IQC548C9YK5I4"
OTPLESS_PACKAGE = "com.meesho.supply"
OTPLESS_LOGIN_URI = "otpless.xn07rn1iqc548c9yk5i4://otpless"
OTPLESS_OTP_HASH = "oBcOM6bXKNc"
OTPLESS_APP_SIGNATURE = "oBcOM6bXKNcqouiPFcR1ur60Z6myTuVIDNSNWuKOlzU"
OTPLESS_UA = "okhttp/4.9.0"
OTPLESS_ORIGIN = "https://otpless.com"

DEVICE_INFO = {
    "platform": "android",
    "vendor": "motorola",
    "browser": "",
    "connection": "",
    "language": "en-IN",
    "cookieEnabled": "",
    "screenWidth": 1080,
    "screenHeight": 2225,
    "userAgent": "Dalvik/2.1.0 (Linux; U; Android 12; moto g(60) Build/S2RI32.32-20-9-9-2) otplesssdk",
    "timezoneOffset": 330,
    "cpuArchitecture": "aarch64",
}

KEY_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+"

# Device fingerprint pool — a fresh one is picked on every FOD refresh so Meesho
# sees a "new device" (new user-agent + device context) each time and can return
# a different offer bucket.
DEVICE_POOL = [
    {"brand": "motorola", "manufacturer": "motorola", "model": "moto g(60)", "os_version": "12", "os": "Android", "screen_dpi": 400, "screen_width": 1080, "screen_height": 2225},
    {"brand": "samsung", "manufacturer": "samsung", "model": "SM-M315F", "os_version": "13", "os": "Android", "screen_dpi": 420, "screen_width": 1080, "screen_height": 2400},
    {"brand": "samsung", "manufacturer": "samsung", "model": "SM-A546E", "os_version": "14", "os": "Android", "screen_dpi": 450, "screen_width": 1080, "screen_height": 2340},
    {"brand": "xiaomi", "manufacturer": "Xiaomi", "model": "M2010J19SI", "os_version": "12", "os": "Android", "screen_dpi": 440, "screen_width": 1080, "screen_height": 2400},
    {"brand": "xiaomi", "manufacturer": "Xiaomi", "model": "23043RP34G", "os_version": "14", "os": "Android", "screen_dpi": 440, "screen_width": 1220, "screen_height": 2712},
    {"brand": "realme", "manufacturer": "realme", "model": "RMX3363", "os_version": "13", "os": "Android", "screen_dpi": 480, "screen_width": 1080, "screen_height": 2400},
    {"brand": "vivo", "manufacturer": "vivo", "model": "V2130", "os_version": "13", "os": "Android", "screen_dpi": 440, "screen_width": 1080, "screen_height": 2376},
    {"brand": "oneplus", "manufacturer": "OnePlus", "model": "CPH2583", "os_version": "14", "os": "Android", "screen_dpi": 450, "screen_width": 1240, "screen_height": 2772},
    {"brand": "oppo", "manufacturer": "OPPO", "model": "CPH2451", "os_version": "13", "os": "Android", "screen_dpi": 440, "screen_width": 1080, "screen_height": 2412},
    {"brand": "tecno", "manufacturer": "TECNO", "model": "CG6", "os_version": "12", "os": "Android", "screen_dpi": 320, "screen_width": 720, "screen_height": 1600},
]

APP_POOL = [
    {"id": 19, "package_name": "com.meesho.supply"},
    {"id": 68, "package_name": "com.flipkart.android"},
    {"id": 112, "package_name": "com.amazon.mShop.android.shopping"},
    {"id": 339, "package_name": "in.swiggy.android"},
    {"id": 106, "package_name": "org.telegram.messenger"},
    {"id": 202, "package_name": "com.google.android.youtube"},
    {"id": 156, "package_name": "com.whatsapp"},
    {"id": 92, "package_name": "com.instagram.android"},
    {"id": 77, "package_name": "com.facebook.katana"},
    {"id": 203, "package_name": "com.google.android.gm"},
    {"id": 88, "package_name": "com.truecaller"},
    {"id": 51, "package_name": "in.org.npci.upiapp"},
    {"id": 201, "package_name": "com.google.android.apps.maps"},
    {"id": 44, "package_name": "com.phonepe.app"},
    {"id": 33, "package_name": "com.paytm"},
    {"id": 210, "package_name": "com.netflix.mediaclient"},
    {"id": 140, "package_name": "com.spotify.music"},
    {"id": 173, "package_name": "com.myjio"},
]

# Offer buckets the app sends to fod-personalisation; "" means auto.
# Rotating these + the device fingerprint is what yields a fresh offer per tap.
BUCKET_POOL = ["", "60", "75", "90", "100", "120", "125", "135", "150", "175", "180", "200"]


def random_device() -> dict:
    """Fresh device fingerprint: random model, GAID, session count, bucket, app list."""
    dev = dict(random.choice(DEVICE_POOL))
    dev["gaid"] = str(uuid.uuid4())
    dev["session_count"] = random.randint(1, 6)
    dev["offer_bucket"] = random.choice(BUCKET_POOL)
    dev["apps_installed"] = [APP_POOL[0]] + random.sample(APP_POOL[1:], random.randint(4, 7))
    return dev


def _fod_body(dev: dict) -> dict:
    """Build the fod-personalisation body for a given device fingerprint."""
    return {
        "offer_bucket": dev["offer_bucket"],
        "from_language_modal": False,
        "brand": dev["brand"],
        "manufacturer": dev["manufacturer"],
        "model": dev["model"],
        "os_version": dev["os_version"],
        "os": dev["os"],
        "carrier": "",
        "connection_type": random.choice(["WIFI", "MOBILE_DATA"]),
        "screen_dpi": dev["screen_dpi"],
        "screen_width": dev["screen_width"],
        "screen_height": dev["screen_height"],
        "apps_installed": dev["apps_installed"],
        "referrer_url": "utm_source=google-adwords&utm_medium=cpc&utm_campaign=first_order_discount_150",
        "campaign_id": "acquisition_fod_150",
        "install_referrer": "utm_source=google-play&utm_medium=organic",
    }


# ---------------------------------------------------------------- crypto
def gen_key() -> str:
    """m8/w;->F(): 16 random chars from the app's charset."""
    return "".join(secrets.choice(KEY_CHARSET) for _ in range(16))


def aes_gcm_encrypt(plaintext: bytes, key: str) -> str:
    """m8/w;->A(): base64(iv12 || AES-128-GCM(plaintext, key[:16])) with 128-bit tag."""
    iv = os.urandom(12)
    ct = AESGCM(key[:16].encode("utf-8")).encrypt(iv, plaintext, None)
    return base64.b64encode(iv + ct).decode("ascii")


def rsa_encrypt(data: str) -> str:
    """i70/b;->a(): base64(RSA/ECB/PKCS1PADDING(data)) with Meesho public key."""
    pub = serialization.load_der_public_key(base64.b64decode(MEESHO_RSA_PUBKEY_B64))
    return base64.b64encode(pub.encrypt(data.encode("utf-8"), padding.PKCS1v15())).decode("ascii")


def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def xo_expiry(xo: str):
    """Extract `exp` from a Meesho composite xo JWT."""
    try:
        outer = json.loads(_b64url_decode(xo.split(".")[0]))
        inner = json.loads(_b64url_decode(xo.split(".")[1]))
        jwt = inner.get("jwt", "")
        payload = json.loads(_b64url_decode(jwt.split(".")[1]))
        return payload.get("exp")
    except Exception:
        return None


# ---------------------------------------------------------------- helpers
def _ts_id() -> str:
    return f"{uuid.uuid4()}-{int(time.time() * 1000)}"


def _api_headers(instance_id: str, xo: str, context: str, session_id: str = None,
                gaid: str = None, session_count: int = None, ua: str = None) -> dict:
    headers = {
        "authorization": MEESHO_AUTH,
        "app-version": APP_VERSION,
        "app-version-code": APP_VERSION_CODE,
        "instance-id": instance_id,
        "country-iso": "in",
        "application-id": APPLICATION_ID,
        "app-session-id": session_id or uuid.uuid4().hex,
        "app-sdk-version": "34",
        "app-client-id": "android",
        "shield-session-id": "",
        "xo": xo,
        "app-iso-language-code": "en",
        "meesho-user-context": context,
        "content-type": "application/json; charset=UTF-8",
        "user-agent": ua or "Cronet",
        "accept-encoding": "gzip, deflate",
    }
    if gaid:
        headers["app-gaid"] = gaid
    if session_count is not None:
        headers["app-session-count"] = str(session_count)
    return headers


def logged_in_headers(account: dict, location: dict = None) -> dict:
    """Full authenticated header set for a SAVED account. The real Android app
    sends app-user-id + u-token + app-user-location + context 'logged_in' on the
    cart / checkout / payments calls; without them the cart API rejects with HTTP
    462 ("Some error occurred") even though the xo is valid.

    account: {mobile, user_id, xo, instance_id}
    location: address JSON for app-user-location (defaults to the saved pin).
    """
    acc = account or {}
    headers = _api_headers(
        instance_id=acc.get("instance_id") or "",
        xo=acc.get("xo") or "",
        context="logged_in",
        # exact session/shield id pairs captured from the real app on this
        # account; the auth code check rejects combinations that don't match.
        session_id=acc.get("app_session_id") or "b2ea8d39-04b3-42e1-8532-e7e29606bfdb",
        ua="Cronet",
    )
    headers["app-version"] = acc.get("app_version") or "28.9"
    headers["app-version-code"] = acc.get("app_version_code") or "853"
    headers["app-sdk-version"] = "31"
    headers["shield-session-id"] = acc.get("shield_session_id") or "bca1ee85f80f45a2b0e4dc480495a192"
    headers["accept-encoding"] = "gzip"
    headers["app-user-id"] = str(acc.get("user_id") or "")
    phone = str(acc.get("mobile") or "")
    if phone:
        headers["u-token"] = base64.b64encode(("+91" + phone).encode()).decode()
    loc = location or {
        "lat": "24.0919", "long": "84.0405", "pincode": "822110",
        "city": "Chainpur", "address_id": "175229093",
    }
    try:
        headers["app-user-location"] = base64.b64encode(
            json.dumps(loc).encode()).decode()
    except Exception:
        pass
    return headers


def _map_fod(resp: dict) -> dict:
    """Map surgical_first_order_discount_v3.offer -> frontend offer shape."""
    v3 = (resp or {}).get("surgical_first_order_discount_v3") or {}
    if not v3.get("enabled", False):
        return {"ok": False, "message": "No FOD offer available right now."}
    offer = v3.get("offer") or {}
    if not offer:
        return {"ok": False, "message": "No FOD offer available right now."}
    return {
        "ok": True,
        "offer": {
            "title": offer.get("offer_title") or "Upto",
            "text": offer.get("offer_text") or "",
            "subtitle": offer.get("offer_subtitle") or "on 1st order",
            "duration": offer.get("offer_duration"),
            "bucket": offer.get("max_offer_value"),
        },
    }


# ---------------------------------------------------------------- FOD
_IDX = 0


def _next_anon_xo():
    """Round-robin through the real anonymous xo pool so every roll uses a
    different server-registered identity -> a different real offer bucket."""
    global _IDX
    pool = anon_xo_pool()
    if not pool:
        return ANON_XO
    entry = pool[_IDX % len(pool)]
    _IDX += 1
    return entry[1]


async def fetch_fod(device: dict = None) -> dict:
    """Compatibility helper: return only a live upstream response. Never
    fabricate a promotional offer when the upstream service fails."""
    dev = device or random_device()
    ua = f"Dalvik/2.1.0 (Linux; U; Android {dev['os_version']}; {dev['model']} Build/) Cronet/137.0.7100.61"
    try:
        xo = _next_anon_xo()
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{MEESHO_API}/1.0/anonymous/fod-personalisation",
                headers=_api_headers(uuid.uuid4().hex, xo, "anonymous",
                                     gaid=dev["gaid"], session_count=dev["session_count"], ua=ua),
                json=_fod_body(dev),
            )
            if resp.status_code == 200:
                mapped = _map_fod(resp.json())
                if mapped.get("ok") and mapped.get("offer"):
                    mapped["offer"]["device"] = dev["model"]
                    return mapped
            return {"ok": False, "live": False, "offer": None,
                    "error": f"Live offer service returned HTTP {resp.status_code}"}
    except Exception as e:
        return {"ok": False, "live": False, "offer": None,
                "error": f"Live offer service unavailable: {type(e).__name__}"}


# ---------------------------------------------------------------- OTPLESS login
def _build_intent_body(phone: str, ts_id: str, in_id: str) -> dict:
    ga_id = str(uuid.uuid4())
    app_info = {
        "platform": "android",
        "manufacturer": "motorola",
        "androidVersion": "31",
        "packageName": OTPLESS_PACKAGE,
        "model": "moto g(60)",
        "appSignature": OTPLESS_APP_SIGNATURE,
        "hasTelegram": "true", "hasMiChat": "false", "hasLine": "false", "hasDiscord": "false",
        "hasSlack": "false", "hasViber": "false", "hasSignal": "false", "hasBotim": "false",
        "hasTrueCaller": "false", "hasWhatsapp": "false", "sdkVersion": "1.3.3",
        "inId": in_id, "tsId": ts_id,
        "isSilentAuthSupported": "true", "isWebAuthnSupported": "true", "isCellularDataEnabled": "false",
        "secureDetail": {"simDetail": {"currentTransportType": "WiFi", "isSimInserted": "false"}},
    }
    device_id_info = {
        "androidId": "aa5e8c37ca4077f7",
        "mediaId": "044507f8402972db73de4f938b76584c89336763bec73f4a9f97b3e36136862f",
        "gaid": ga_id,
    }
    metadata = json.dumps({
        "appInfo": json.dumps(app_info),
        "deviceInfo": json.dumps(DEVICE_INFO),
        "deviceIdInfo": json.dumps(device_id_info),
    })
    return {
        "selectedCountryCode": "+91",
        "mobile": f"91{phone}",
        "silentAuthEnabled": False,
        "hasWhatsapp": "false",
        "deliveryChannel": "SMS",
        "metadata": metadata,
        "triggerWebauthn": False,
        "telephonyInfo": {"isMobileDataOn": False, "hasReadPhoneStatePermission": False, "all": [{}]},
        "clientMetaData": json.dumps({"tid": secrets.token_urlsafe(12)[:16]}),
        "asId": "",
        "isViSnaWhitelisted": True,
        "isAirtelSnaWhitelisted": True,
        "isAutoIntent": True,
        "origin": "https://otpless.com",
        "version": "V4",
        "tsId": ts_id,
        "inId": in_id,
        "deviceInfo": json.dumps(DEVICE_INFO),
        "loginUri": OTPLESS_LOGIN_URI,
        "appId": OTPLESS_APP_ID,
        "isHeadless": True,
        "packageName": OTPLESS_PACKAGE,
        "package": OTPLESS_PACKAGE,
        "otpHash": OTPLESS_OTP_HASH,
        "platform": "HEADLESS",
    }


async def request_meesho_otp(phone: str) -> dict:
    """Start OTPLESS login: get state, then send OTP intent. OTP arrives via WhatsApp/SMS."""
    ts_id, in_id = _ts_id(), _ts_id()
    headers = {"user-agent": OTPLESS_UA}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            state_resp = await client.get(
                "https://user-auth.otpless.app/v2/state",
                params={
                    "origin": OTPLESS_ORIGIN,
                    "version": "V3",
                    "tsId": ts_id,
                    "inId": in_id,
                    "isHeadless": "true",
                    "platform": "android",
                    "isLoginPage": "false",
                    "packageName": OTPLESS_PACKAGE,
                    "package": OTPLESS_PACKAGE,
                    "appId": OTPLESS_APP_ID,
                    "loginUri": OTPLESS_LOGIN_URI,
                    "deviceInfo": json.dumps(DEVICE_INFO),
                },
                headers=headers,
            )
            state = (state_resp.json() or {}).get("state")
            if not state:
                return {"ok": False, "error": "Could not start login session (state failed)."}

            intent_resp = await client.post(
                f"https://user-auth.otpless.app/v3/lp/user/transaction/intent/{state}",
                headers={**headers, "content-type": "application/json; charset=utf-8"},
                json=_build_intent_body(phone, ts_id, in_id),
            )
            data = intent_resp.json() or {}
            leap = data.get("quantumLeap") or {}
            if not leap.get("uid") or not leap.get("channelAuthToken"):
                return {"ok": False, "error": f"OTP request rejected: {json.dumps(data)[:200]}"}
            return {
                "ok": True,
                "session": {
                    "state": state,
                    "uid": leap["uid"],
                    "token": leap["channelAuthToken"],
                    "as_id": leap.get("asId", ""),
                    "ts_id": ts_id,
                    "in_id": in_id,
                    "instance_id": uuid.uuid4().hex,
                },
            }
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def check_number_registered(phone: str) -> dict:
    """Check if a phone number is registered on Meesho via OTPLESS.
    Returns {"registered": bool, "phone": str, "error": str|None}.
    Sends an OTPLESS intent; if the number is not registered the API rejects it."""
    ts_id, in_id = _ts_id(), _ts_id()
    headers = {"user-agent": OTPLESS_UA}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            state_resp = await client.get(
                "https://user-auth.otpless.app/v2/state",
                params={
                    "origin": OTPLESS_ORIGIN, "version": "V3", "tsId": ts_id, "inId": in_id,
                    "isHeadless": "true", "platform": "android", "isLoginPage": "false",
                    "packageName": OTPLESS_PACKAGE, "package": OTPLESS_PACKAGE,
                    "appId": OTPLESS_APP_ID, "loginUri": OTPLESS_LOGIN_URI,
                    "deviceInfo": json.dumps(DEVICE_INFO),
                },
                headers=headers,
            )
            state = (state_resp.json() or {}).get("state")
            if not state:
                return {"registered": False, "phone": phone, "error": "state_failed"}
            intent_resp = await client.post(
                f"https://user-auth.otpless.app/v3/lp/user/transaction/intent/{state}",
                headers={**headers, "content-type": "application/json; charset=utf-8"},
                json=_build_intent_body(phone, ts_id, in_id),
            )
            data = intent_resp.json() or {}
            leap = data.get("quantumLeap") or {}
            if leap.get("uid") and leap.get("channelAuthToken"):
                return {"registered": True, "phone": phone, "error": None}
            err = data.get("errorMessage") or data.get("error") or json.dumps(data)[:200]
            return {"registered": False, "phone": phone, "error": err}
    except Exception as e:
        return {"registered": False, "phone": phone, "error": str(e)}


async def verify_meesho_otp(phone: str, otp: str, session: dict) -> dict:
    """Verify OTP via OTPLESS, then exchange oneTap token + encrypted id_token for the
    Meesho logged-in xo (xoox.xo)."""
    otp_headers = {"user-agent": OTPLESS_UA, "content-type": "application/json; charset=utf-8"}
    otp_body = {
        "selectedCountryCode": "91",
        "mobile": phone,
        "otp": otp,
        "value": f"91{phone}",
        "isOTPAutoRead": "false",
        "uid": session["uid"],
        "token": session["token"],
        "asId": session["as_id"],
        "origin": OTPLESS_ORIGIN,
        "version": "V4",
        "tsId": session["ts_id"],
        "inId": session["in_id"],
        "deviceInfo": json.dumps(DEVICE_INFO, separators=(",", ":")),
        "loginUri": OTPLESS_LOGIN_URI,
        "appId": OTPLESS_APP_ID,
        "isHeadless": True,
        "packageName": OTPLESS_PACKAGE,
        "package": OTPLESS_PACKAGE,
        "otpHash": OTPLESS_OTP_HASH,
        "platform": "HEADLESS",
    }
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            verify_resp = await client.post(
                f"https://user-auth.otpless.app/v3/lp/user/transaction/otp/{session['state']}",
                headers=otp_headers,
                json=otp_body,
            )
            data = verify_resp.json() or {}
            one_tap = data.get("oneTap") or {}
            token = one_tap.get("token")
            id_token = (one_tap.get("merchantUserInfo") or {}).get("idToken")
            if not token or not id_token:
                status = (data.get("authDetail") or {}).get("status", "FAILED")
                return {"ok": False, "error": f"OTP verification failed ({status})."}

            # Build encrypted login payload (APK: m8/w + i70/b)
            key = gen_key()
            login_body = {
                "login_type": "otpless",
                "otpless": {
                    "token": token,
                    "id_token": aes_gcm_encrypt(id_token.encode("utf-8"), key),
                    "aes_key_encrypted": rsa_encrypt(key),
                    "version": "v2",
                },
                "ga_id": str(uuid.uuid4()),
            }
            login_resp = await client.post(
                f"{MEESHO_API}/2.0/user/login",
                headers=_api_headers(session["instance_id"], ANON_XO, "anonymous"),
                json=login_body,
            )
            if login_resp.status_code != 200:
                return {"ok": False, "error": f"Login failed (HTTP {login_resp.status_code}): {login_resp.text[:200]}"}
            ldata = login_resp.json() or {}
            user = ldata.get("user") or {}
            xo = (ldata.get("xoox") or {}).get("xo") or ""
            if not xo:
                return {"ok": False, "error": "Login failed: no xo in response."}
            return {
                "ok": True,
                "user_id": user.get("user_id"),
                "phone": user.get("phone"),
                "xo": xo,
                "xo_exp": xo_expiry(xo),
                "instance_id": session["instance_id"],
                "is_new": bool(user.get("new")),
                "sign_up_date": user.get("sign_up_date") or user.get("sign_up_date_iso"),
            }
    except Exception as e:
        return {"ok": False, "error": str(e)}




# ---- embedded Meesho API client (kept as a module-like namespace for compatibility) ----
import types as _types
_meesho_public = {k:v for k,v in globals().items() if not k.startswith("__")}
meesho_api = _types.SimpleNamespace(**_meesho_public)
del _meesho_public, _types

import os
import asyncio
import json
import re
import datetime
import uuid
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import time
import copy

# ================= CONFIGURATION =================
# No Telegram bot. Pure web. Host URL is resolved from env or detected.
HOST_URL = os.getenv("WEBAPP_URL", "").strip().rstrip("/")
WEBAPP_URL = HOST_URL or "http://localhost:8000"

STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state")
STATE_FILE = os.path.join(STATE_DIR, "db.json")

# ================= DATABASE / STATE =================
db = {
    "accounts": [],
    "active_id": None,
    "referral_link": "",
    "addresses": [
        {
            "id": 101,
            "name": "User Demo",
            "mobile": "9876543210",
            "pin": "110001",
            "city": "New Delhi",
            "state": "Delhi",
            "address_line_1": "Connaught Place",
            "address_line_2": "",
            "landmark": "",
            "address_type": "Home",
            "pin_serviceable": True,
        }
    ],
    "cart": {"items": [], "total_quantity": 0, "effective_total": 0, "effective_online": 0, "address": None, "price_break_up": [], "cart_session": ""},
    "orders": [],
    "pending_binds": {},  # number -> {offer, request_id, instance_id}
    "phone_status": {},  # number -> {registered, is_new, sign_up_date, checked_at} verified via a real login
    "picked_offer": None,  # last rolled offer the user chose to continue with
    "devices": {},  # device_id -> {cart, orders} per-device isolation
}


def _default_state():
    """A brand-new per-browser db, seeded from the shared login template so a
    fresh browser starts with the saved accounts, then evolves independently."""
    seed = globals().get("SEED") or db
    return {
        "accounts": copy.deepcopy(seed.get("accounts") or []),
        "active_id": copy.deepcopy(seed.get("active_id")),
        "referral_link": seed.get("referral_link", ""),
        "addresses": [],
        "cart": {"items": [], "total_quantity": 0, "effective_total": 0, "effective_online": 0, "address": None, "price_break_up": [], "cart_session": ""},
        "orders": [],
        "pending_binds": {},
        "phone_status": copy.deepcopy(seed.get("phone_status") or {}),
        "picked_offer": copy.deepcopy(seed.get("picked_offer")),
        "auto_cancel_orders": True,
    }


def _persist():
    """Save the full per-browser registry (each browser's entire db) plus a
    top-level legacy snapshot of the last-writer's state, so nothing is lost on
    restart and old clients still find global cart/orders keys."""
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        cur = globals().get("db") or db
        slim = {
            "accounts": cur.get("accounts") or (globals().get("SEED") or {}).get("accounts") or [],
            "active_id": cur.get("active_id") if cur.get("active_id") is not None else (globals().get("SEED") or {}).get("active_id"),
            "referral_link": cur.get("referral_link") or "",
            "addresses": [],
            "phone_status": cur.get("phone_status") or {},
            "picked_offer": cur.get("picked_offer"),
            "cart": cur.get("cart") or {},
            "orders": cur.get("orders") or [],
        }
        # Per-browser dbs: devices[id] holds that browser's FULL state.
        per_dev = {}
        for ns, st in (globals().get("DEVICES") or {}).items():
            if not isinstance(st, dict):
                continue
            clean = {k: copy.deepcopy(v) for k, v in st.items() if k not in ("devices",)}
            per_dev[ns] = clean
        slim["devices"] = per_dev
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(slim, f, ensure_ascii=False)
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass


def _restore():
    try:
        if not os.path.exists(STATE_FILE):
            return
        with open(STATE_FILE) as f:
            loaded = json.load(f)
        for k, v in loaded.items():
            if k == "cart":
                db["cart"].update(v or {})
            elif k == "devices":
                devs = v or {}
                for ns, entry in devs.items():
                    if not isinstance(entry, dict):
                        continue
                    if isinstance(entry.get("accounts"), list):
                        db["devices"][ns] = entry
                    else:  # legacy per-device cart/orders -> full per-device db
                        st = _default_state()
                        st["cart"].update(entry.get("cart") or {})
                        st["orders"] = entry.get("orders") or []
                        db["devices"][ns] = st
            elif k != "pending_binds":
                db[k] = v
        # ONE-TIME MIGRATION: legacy global address book -> per-account buckets.
        # An address is only trusted for an account when it demonstrably belongs
        # to it (matching userId or mobile). Unclaimed ones are dropped so they
        # can never surface for the wrong account.
        legacy = db.get("addresses") or []
        if legacy and isinstance(legacy, list):
            for a in legacy:
                if not isinstance(a, dict) or not a.get("id"):
                    continue
                for acc in db["accounts"]:
                    uid = a.get("user_id") or a.get("userId")
                    mob = str(a.get("mobile") or "")
                    if (uid is not None and str(uid) == str(acc.get("user_id"))) or \
                       (mob and mob == str(acc.get("mobile"))):
                        acc.setdefault("addresses", [])
                        if not any(x.get("id") == a["id"] for x in acc["addresses"]):
                            acc["addresses"].insert(0, a)
                        break
        db["addresses"] = []
    except Exception:
        pass


_restore()

# Shared login template + per-browser registry. `db` is swapped per request by
# the middleware; SEED/DEVICES are never reassigned.
SEED = db
DEVICES = db["devices"]


def _tg_user_id(init_data):
    """Telegram user id from X-Tg-Init-Data, or None for plain browsers."""
    if not init_data:
        return None
    try:
        from urllib.parse import parse_qs
        qs = parse_qs(init_data or "")
        raw = (qs.get("user") or [None])[0]
        if not raw:
            return None
        obj = json.loads(raw)
        ident = obj.get("id") if isinstance(obj, dict) else None
        return int(ident) if ident is not None else None
    except Exception:
        return None

# Legacy local promo pool removed: promotional values must come from the live
# account/server response and are never generated locally.
def roll_fod():
    return None



def active_offer():
    """FOD to apply right now: bound to the active account ONLY while it is a
    genuine first-time buyer (is_first_order). Real Meesho applies the first-order
    discount server-side against the account (Checkout$UserMeta.is_first_order),
    not against the anonymous display card. Once a returning buyer, no offer —
    never fabricate a FREE ORDER for accounts that aren't first-time buyers."""
    acc = next((a for a in db["accounts"] if a.get("id") == db["active_id"]), None)
    if not acc or not acc.get("is_first_order"):
        return None
    if acc.get("order_placed"):
        return None
    return acc.get("bound_offer") or db.get("picked_offer") or None


def apply_fod(mrp, offer=None):
    """Return (final_price, savings_text, pct). Applies the FOD percentage/cashback/flat."""
    offer = offer or active_offer()
    if not offer:
        return mrp, "No Discount", 0
    pct = int(offer.get("pct") or 0)
    cb = offer.get("cashback")
    flat = int(offer.get("flat") or 0)
    buck = (offer.get("bucket") or offer.get("max_offer_value") or 0)
    try:
        mrp = float(mrp or 0)
        buck = float(buck or 0)
        flat = float(flat or 0)
    except Exception:
        mrp = 0.0
        buck = 0.0
        flat = 0.0
    if pct >= 100:
        return 0.0, "100% Free", 100
    if cb:
        pay = max(0, mrp - float(cb))
        return round(pay, 2), f"₹{int(cb)} Cashback", None
    if flat:
        pay = max(0, mrp - flat)
        return round(pay, 2), f"Upto ₹{int(flat)} OFF", None
    if buck:
        pay = max(0, mrp - buck)
        return round(pay, 2), f"Upto ₹{int(buck)} OFF", None
    if pct > 0:
        pay = mrp * (100 - pct) / 100.0
        return round(pay, 2), f"{pct}% OFF", pct
    return mrp, "No Discount", 0

# ================= LIVE MEESHO API CLIENT =================
C = {
    "ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36",
}


def meesho_headers(extra=None):
    h = {
        "Host": "www.meesho.com",
        "User-Agent": C["ua"],
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "meesho-iso-country-code": "IN",
        "origin": "https://www.meesho.com",
        "referer": "https://www.meesho.com/",
        "sec-ch-ua-platform": '"Android"',
        "sec-ch-ua-mobile": "?1",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }
    if extra:
        h.update(extra)
    return h


def _as_json(resp):
    """Try to parse JSON; if Meesho returns an HTML challenge/encoded blob,
    return None so callers fall back to demo data instead of hard-erroring."""
    try:
        return resp.json()
    except Exception:
        return None


async def meesho_request(method, url, *, headers=None, json=None, params=None, data=None, timeout=20):
    last = None
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.request(method, url, headers=headers or meesho_headers(), json=json, params=params, data=data)
                if resp.status_code >= 500 or resp.status_code in (408, 429):
                    last = resp
                    await asyncio.sleep(0.8)
                    continue
                return resp
        except Exception as exc:
            last = exc
            await asyncio.sleep(0.8)
    if isinstance(last, Exception):
        return None
    return last


# ---------------- AUTH (real OTPLESS flow, demo fallback) ----------------
# Otpless session for a phone is cached so verify can complete the exchange
# even when it's a different HTTP request than the one that sent the OTP.
_otp_sessions = {}  # phone -> Otpless session dict


async def meesho_request_otp(phone_number: str):
    """Start a REAL OTPLESS login for the phone. No demo fallback: if the live
    request fails, report the failure so the caller can surface a real error."""
    phone = str(phone_number)[-10:]
    err = None
    try:
        res = await meesho_api.request_meesho_otp(phone)
        if res.get("ok") and res.get("session"):
            _otp_sessions[phone] = res["session"]
            return {
                "ok": True,
                "request_id": res["session"]["state"],
                "instance_id": res["session"]["instance_id"],
                "remark": "otpless",
                "live": True,
            }
        err = res.get("error") or "OTP request rejected"
    except Exception as e:
        err = str(e) or "OTP request error"
    return {"ok": False, "live": False, "error": f"Could not send OTP: {err}"}


async def meesho_verify_otp(phone_number: str, otp: str, request_id: str, instance_id: str):
    """Verify a REAL OTP against the active OTPLESS session only. No demo accept:
    a wrong/missing/expired OTP is rejected outright (never fabricates an account)."""
    phone = str(phone_number)[-10:]
    session = _otp_sessions.get(phone)
    if not (session and str(request_id) == str(session.get("state"))):
        return {"ok": False, "error": "No active OTP session — request a new OTP.",
                "live": True, "wrong_otp": True}
    try:
        res = await meesho_api.verify_meesho_otp(phone, otp, session)
        if res.get("ok"):
            _otp_sessions.pop(phone, None)
            return {
                "ok": True,
                "user_id": res.get("user_id"),
                "xo": res.get("xo"),
                "xo_exp": res.get("xo_exp"),
                "instance_id": res.get("instance_id", instance_id),
                "live": True,
                "is_new": res.get("is_new"),
                "sign_up_date": res.get("sign_up_date"),
            }
        return {
            "ok": False,
            "error": (res.get("error") or "Incorrect OTP"),
            "live": True,
            "wrong_otp": True,
        }
    except Exception as e:
        return {"ok": False, "error": f"OTP verify error: {e}", "live": True,
                "wrong_otp": True}


def record_phone_truth(phone: str, res: dict):
    """Store the verified registered/fresh status for a phone after a successful
    live login, so future no-OTP checks can answer instantly and accurately."""
    phone = str(phone)[-10:]
    if not (res.get("live") and "is_new" in res):
        return
    db.setdefault("phone_status", {})[phone] = {
        "registered": (res.get("is_new") is False),
        "is_new": res.get("is_new"),
        "sign_up_date": res.get("sign_up_date"),
        "checked_at": time.time(),
    }



# ---------------- CATALOG / SEARCH ----------------
SEARCH_FILTER = {
    "type": "text_search", "sort_option": None, "selected_filters": [],
    "current_row_filters": [], "session_state": None, "selectedFilterIds": [],
    "isClearFilterClicked": False, "query": "", "intent_payload": None,
    "is_voice_search": False, "is_autocorrect_reverted": False,
    "enabled_mid_feed_filters": False, "mid_feed_filter_variant": None,
    "selected_mid_feed_filter_priority": None, "hvf_ui_version": None,
    "hvf_config": None,
}

def _prod_xo(extra=None):
    """Grab a real anonymous xo from the pool. Returns (xo_jwt, instance_id)."""
    try:
        
        import json as _json
        xo = _next_anon_xo()
        if not xo:
            xo = "32c4d8137cn9eb493a1921f203173080"
        instance_id = ""
        try:
            inner = _json.loads(_b64url_decode(xo.split(".")[1]))
            jwt = inner.get("jwt", "")
            payload = _json.loads(_b64url_decode(jwt.split(".")[1]))
            instance_id = payload.get("https://meesho.com/instance_id", "")
        except Exception:
            instance_id = ""
        return xo, instance_id
    except Exception:
        return "32c4d8137cn9eb493a1921f203173080", "9ba95af4da434df29f01417f7ed5cd37"

def _prod_headers(extra=None):
    xo, instance_id = _prod_xo()
    h = {
        "Host": "prod.meeshoapi.com",
        "authorization": "32c4d8137cn9eb493a1921f203173080",
        "x-wishlist-aggregation-required": "false",
        "app-version": "29.1",
        "app-version-code": "860",
        "instance-id": instance_id or "9ba95af4da434df29f01417f7ed5cd37",
        "country-iso": "in",
        "application-id": "com.meesho.supply",
        "app-session-id": "a314f53b-bd57-4246-8f76-d56a14d819c9",
        "app-sdk-version": "33",
        "app-client-id": "android",
        "shield-session-id": "",
        "xo": xo,
        "app-iso-language-code": "en",
        "meesho-user-context": "anonymous",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "okhttp/4.9.0",
    }
    if extra:
        h.update(extra)
    return h

def _active_account():
    """The currently selected saved account, or None."""
    acc = next((a for a in db["accounts"] if str(a.get("id")) == str(db.get("active_id"))), None)
    return acc


def _account_addresses():
    """Address book scoped to the ACTIVE account ONLY. Never falls back to other
    accounts' addresses — a foreign address_id bound at checkout makes
    /api/4.0/preorders reject with a generic 500."""
    acc = _active_account()
    if not acc:
        return []
    acc.setdefault("addresses", [])
    return acc["addresses"]


def _set_account_addresses(addrs):
    acc = _active_account()
    if acc is None:
        return
    acc["addresses"] = [a for a in addrs if isinstance(a, dict) and a.get("id")]


def _account_address_by_id(addr_id=None):
    """Find an address by id within the ACTIVE account's own address book."""
    addrs = _account_addresses()
    if addr_id is not None:
        for a in addrs:
            if a.get("id") == addr_id or str(a.get("id")) == str(addr_id):
                return a
    for a in addrs:
        if a.get("id") and a.get("valid") is not False and a.get("pin_serviceable") is not False:
            return a
    return addrs[0] if addrs else None


def _address_location(acc=None):
    """Build the app-user-location header JSON for a given account from its OWN
    primary (first valid) address. CRITICAL: the location's address_id must belong
    to this account — binding a foreign address_id makes /api/4.0/preorders
    reject with CART_INELIGIBLE / generic 500. Returns None if no address."""
    acc = acc or _active_account()
    if not acc:
        return None
    addrs = acc.get("addresses") or []
    addr = None
    for a in addrs:
        if isinstance(a, dict) and a.get("id") and a.get("pin_serviceable") is not False and a.get("valid") is not False:
            addr = a
            break
    if addr is None:
        addr = next((a for a in addrs if isinstance(a, dict) and a.get("id")), None)
    if not addr:
        return None
    return {
        "lat": str(addr.get("latitude") or addr.get("lat") or ""),
        "long": str(addr.get("longitude") or addr.get("lng") or ""),
        "pincode": str(addr.get("pin") or ""),
        "city": addr.get("city") or "",
        "address_id": str(addr.get("id")),
    }


def _active_headers():
    """Full LOGGED-IN header set for the active saved account, built from its real
    xo + instance_id + user_id + mobile. This is what the real app sends for the
    cart/checkout APIs (context 'logged_in', app-user-id, u-token, app-user-location).
    The app-user-location is derived from the account's OWN address so checkout
    never binds a foreign address_id (which makes preorders reject with
    CART_INELIGIBLE / generic 500). Returns None when there is no usable saved
    session -> endpoints must error real."""
    acc = _active_account()
    if not acc:
        return None
    if not (acc.get("xo") and acc.get("instance_id") and acc.get("user_id") and acc.get("mobile")):
        return None
    try:
        exp = acc.get("xo_exp")
        if exp and float(exp) < time.time():
            return None
    except Exception:
        pass
    try:
        return meesho_api.logged_in_headers(acc, location=_address_location(acc))
    except Exception:
        return None

def _cdn_image(raw):
    """Normalize a Meesho CDN URL. Bare catalog cover paths end with '/' and 404
    without a suffix -> append _512.jpg. Otherwise pass through as-is."""
    if not raw:
        return ""
    raw = str(raw)
    if raw.endswith("/cover/1/") or raw.endswith("/cover/"):
        return raw + "_512.jpg"
    if raw.endswith("/"):
        return raw + "_512.jpg"
    return raw


async def meesho_search(query: str, cursor=None, offset=0, session_id=None):
    filt = dict(SEARCH_FILTER); filt["query"] = query
    body = {
        "filter": filt,
        "search_session_id": session_id, "cursor": cursor, "offset": offset, "limit": 20,
        "supplier_id": None, "featured_collection_type": None,
        "meta": {"recent_searches": [query]}, "retry_count": 0,
        "product_listing_page_id": None,
    }
    resp = await meesho_request(
        "POST", "https://prod.meeshoapi.com/api/3.0/anonymous/catalogs",
        json=body, headers=_prod_headers(),
    )
    if resp and resp.status_code == 200:
        data = _as_json(resp)
        catalogs = (data or {}).get("catalogs") or []
        if catalogs:
            out = []
            for c in catalogs:
                pv = c.get("prepaid_price_view") or {}
                price = pv.get("prepaid_price") or c.get("min_catalog_price") or c.get("min_product_price") or 0
                original = c.get("original_price") or 0
                pimgs = c.get("product_images") or []
                img = ""
                if isinstance(pimgs, list) and pimgs:
                    first = pimgs[0]
                    if isinstance(first, dict):
                        img = first.get("url") or ""
                    else:
                        img = str(first)
                if not img:
                    img = _cdn_image(c.get("image") or "")
                rev = c.get("catalog_reviews_summary") or {}
                fod = None
                po = c.get("promo_offer") or {}
                if po:
                    fod = {
                        "type": po.get("type"),
                        "name": po.get("name"),
                        "discount_text": po.get("discount_text"),
                        "amount": po.get("amount"),
                        "is_applied": po.get("is_applied"),
                    }
                out.append({
                    "product_id": int(c.get("hero_pid") or c.get("id") or 0),  # REAL product id (hero_pid), NOT the catalog id
                    "catalog_id": int(c.get("id") or 0),                        # catalog id — used for PDP/reviews
                    "type": c.get("type", "catalog"),
                    "name": c.get("name"),
                    "price": price,
                    "original_price": original,
                    "discount_text": c.get("discount_text") or "",
                    "rating": {"average": rev.get("average_rating"), "count": rev.get("rating_count"), "score": rev.get("average_rating")},
                    "rating_count": rev.get("rating_count"),
                    "image": img or (f"https://images.meesho.com/images/catalogs/{c.get('id')}/cover/1/_512.jpg" if c.get("id") else ""),
                    "images": [img] if img else [],
                    "description": c.get("description"),
                    "min_product_price": c.get("min_product_price") or 0,
                    "min_catalog_price": c.get("min_catalog_price") or 0,
                    "supplier_id": None, "supplier_name": None, "mall_verified": False,
                    "fod": fod,
                })
            return {"catalogs": out, "live": True,
                    "cursor": data.get("cursor"), "search_session_id": data.get("search_session_id"),
                    "corrected_term": data.get("corrected_search_term")}
    return None

async def meesho_search_suggest(prefix: str):
    resp = await meesho_request(
        "GET", "https://prod.meeshoapi.com/api/3.0/anonymous/search/suggest",
        params={"prefix": prefix},
        headers=_prod_headers(),
    )
    if resp and resp.status_code == 200:
        data = _as_json(resp)
        items = ((data or {}).get("suggestions") or {}).get("global") or {}
        return items.get("items") or []
    return None


def _normalize_highlights(p: dict) -> list:
    """Map static product_details -> [{name, value}] highlight cells."""
    out = []
    try:
        pd = p.get("product_details") or {}
        attrs = []
        for section in ("product_highlights", "additional_details"):
            sec = pd.get(section) or {}
            for a in sec.get("attributes") or []:
                attrs.append(a)
        seen = set()
        for a in attrs:
            n = str(a.get("display_name") or a.get("field_name") or "").strip()
            v = str(a.get("value") or "").strip()
            if n and v and (n, v) not in seen:
                seen.add((n, v))
                out.append({"name": n, "value": v})
    except Exception:
        pass
    return out[:8]


def _normalize_review_sentiment(p: dict) -> list:
    """Map review_attributes -> [{label, icon, positive_pct, stroke_color, bg_color, total}]."""
    out = []
    try:
        ra = p.get("review_attributes") or {}
        for a in ra.get("attributes") or []:
            votes = (a.get("description") or {}).get("attribute_votes") or {}
            total = (votes.get("total") or {}).get("count")
            out.append({
                "label": a.get("label"),
                "icon": a.get("icon"),
                "positive_pct": (votes.get("positive") or {}).get("percentage"),
                "stroke_color": a.get("stroke_color"),
                "bg_color": a.get("background_color"),
                "total": total,
            })
    except Exception:
        pass
    return out


def _normalize_sizes(variations) -> list:
    """Turn supplier variations (list of size-name strings) into [{variation_id, name}]."""
    out = []
    if not isinstance(variations, list):
        return out
    for i, v in enumerate(variations):
        name = str(v or "")
        if name and name.strip():
            out.append({"variation_id": i + 1, "name": name.strip()})
    return out


def _real_variations(inventory) -> list:
    """Real variation map from Meesho inventory items: inventory is a list of
    {"variation": {"id": <real id>, "name": "Free Size"}, "in_stock": bool}."""
    out = []
    if not isinstance(inventory, list):
        return out
    for it in inventory:
        v = it.get("variation") if isinstance(it, dict) else None
        if not isinstance(v, dict) or not v.get("id"):
            continue
        name = str(v.get("name") or "Free Size")
        if name.strip():
            out.append({"variation_id": int(v.get("id")), "name": name.strip(),
                        "in_stock": bool(it.get("in_stock"))})
    return out


async def meesho_product(product_id):
    if product_id in (None, 1001):
        return None  # demo id -> force fallback
    headers = _prod_headers()
    static = await meesho_request(
        "GET", "https://prod.meeshoapi.com/api/3.0/product/static",
        params={"id": product_id, "context": "widget", "ad_active": "true"},
        headers=headers,
    )
    dynamic = await meesho_request(
        "GET", "https://prod.meeshoapi.com/api/3.0/product/dynamic",
        params={"id": product_id, "context": "widget", "origin": "widget"},
        headers=headers,
    )
    sc = (static and static.status_code == 200 and _as_json(static) or {}).get("catalog") or {}
    sp = (static and static.status_code == 200 and _as_json(static) or {}).get("product") or {}
    dc = (dynamic and dynamic.status_code == 200 and _as_json(dynamic) or {}).get("catalog") or {}
    dp = (dynamic and dynamic.status_code == 200 and _as_json(dynamic) or {}).get("product") or {}
    if not sp and not dp:
        return None
    p = sp or dp
    suppliers = dp.get("suppliers") or sp.get("suppliers") or []
    sup = suppliers[0] if isinstance(suppliers, list) and suppliers else {}
    pv = sup.get("prepaid_price_view") or {}
    final = pv.get("prepaid_price") or dp.get("min_product_price") or sup.get("price") or p.get("mrp") or 0
    mrp = sup.get("original_price") or p.get("mrp") or final
    imgs = dp.get("catalog_product_images") or sp.get("catalog_product_images") or []
    images = []
    if isinstance(imgs, list):
        for im in imgs[:6]:
            u = im.get("url") if isinstance(im, dict) else im
            if u:
                images.append(u)
    elif isinstance(imgs, str):
        images = [imgs]
    sizes = _real_variations(sup.get("inventory"))
    if not sizes:
        sizes = _real_variations(((sc.get("products") or dc.get("products") or [{}])[0]).get("inventory"))
    price_type_id = sup.get("price_type_id") or sc.get("price_type_id") or dc.get("price_type_id") or "premium_return_price"
    desc = sp.get("description") or dp.get("description") or ""
    highlights = _normalize_highlights(sp) if sp else []
    review_sentiment = _normalize_review_sentiment(sp) if sp else []
    rating = sup.get("average_rating")
    rating_count = sup.get("rating_count")
    return {
        "product_id": int(p.get("id") or product_id),
        "catalog_id": int(sp.get("catalog_id") or p.get("catalog_id") or product_id),
        "name": p.get("name") or "Product",
        "brand": sp.get("brand_name") or dp.get("brand_name") or "",
        "price": final,
        "mrp": mrp,
        "list_price": sup.get("price") or final,
        "original_price": mrp,
        "images": images,
        "image": images[0] if images else None,
        "sizes": sizes,
        "supplier_id": sup.get("id"),
        "supplier_name": sup.get("name"),
        "mall_verified": bool(sup.get("mall_verified")),
        "full_details": desc,
        "description": desc,
        "highlights": highlights,
        "supplier_rating": rating,
        "supplier_rating_count": rating_count,
        "review_sentiment": review_sentiment,
        "in_stock": bool(sup.get("in_stock", True)) if "in_stock" in sup else None,
        "rating": rating,
        "rating_count": rating_count,
        "discount_text": sup.get("discount_text") or "",
        "price_type_id": price_type_id,
    }


async def meesho_check_eligibility(phone_number: str):
    """A phone number's private offer cannot be inferred from an anonymous
    request. Authenticate the number first; then _account_real_fod() is the
    authoritative source for that account."""
    return {"live": False, "eligible": False, "bucket": None, "message": None,
            "error": "Authenticate this number first; the live offer is checked from its account session."}


async def _live_product(pid):
    """Return a merged LIVE product dict for a real Meesho product id, or None if
    the live PDP could not be loaded. NO demo fallback — callers must error on None."""
    pid = int(pid or 0)
    if not pid:
        return None
    try:
        return await meesho_product(pid)
    except Exception:
        return None


# ================= FASTAPI APP =================
app = FastAPI(title="Meesho Auto Order Web", lifespan=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ================= DEVICE ISOLATION =================
# FULL per-user + per-browser db isolation (NOT by IP/network — by the
# browser's X-Device-ID + Telegram user id). Each browser gets its OWN complete
# db: accounts, active_id, address book, cart, orders, offers — everything.

# ================= SAAS · USERS / PLANS / SESSIONS =================
USERS_FILE = os.path.join(STATE_DIR, "users.json")
SECRET_FILE = os.path.join(STATE_DIR, "secret.key")

TRIAL_FREE_ORDERS = 10  # lifetime free order cap for the Free/trial plan

PLANS = {
    "free":    {"key": "free",    "label": "Free",      "price": "₹0",      "devices": 1, "orders": 10, "trial": True, "orders_left_for": "trial", "color": "#9AA3B8", "blurb": "Free trial · 10 free orders. 1 linked account · every order free · no card needed."},
    "pro":     {"key": "pro",     "label": "Pro",       "price": "₹299/mo", "devices": 3, "orders": 60, "color": "#2F6BFF", "blurb": "For daily shoppers. 3 accounts · 60 orders/day · priority auto-cancel."},
    "proplus": {"key": "proplus", "label": "Pro Plus",  "price": "₹699/mo", "devices": 0, "orders": 0,  "color": "#7C5CFF", "blurb": "For resellers. Unlimited accounts & orders · everything unlocked."},
}


def _secret():
    s = ""
    try:
        if os.path.exists(SECRET_FILE):
            s = open(SECRET_FILE).read().strip()
    except Exception:
        pass
    if not s:
        s = uuid.uuid4().hex + uuid.uuid4().hex
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with open(SECRET_FILE, "w") as f:
                f.write(s)
        except Exception:
            pass
    return s


SECRET = _secret()  # signed-token key, persisted so tokens survive restarts


def _load_users():
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_users(users):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = USERS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(users, f, ensure_ascii=False, indent=1)
        os.replace(tmp, USERS_FILE)
    except Exception:
        pass


def _ensure_admin():
    users = _load_users()
    user = os.getenv("ADMIN_USER", "admin").strip()
    pwd = os.getenv("ADMIN_PASS", "admin123")
    if user and user not in users:
        users[user] = {"id": 1, "username": user, "password": pwd, "role": "admin",
                       "plan": "proplus", "active": True, "created_at": int(time.time()),
                       "last_seen": int(time.time()), "used": {"date": "", "count": 0}, "trial_used": 0}
        _save_users(users)
    return users


def _issue_token(username, ttl=7 * 86400):
    """Signed session token (user.exp.hmac). No server-side session store."""
    import hashlib, hmac as _hmac, base64
    payload = base64.urlsafe_b64encode(
        json.dumps({"u": username, "e": int(time.time()) + ttl}).encode()).decode().rstrip("=")
    sig = _hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig


def _verify_token(token):
    import hashlib, hmac as _hmac
    token = str(token or "")
    if "." not in token:
        return None
    payload, sig = token.rsplit(".", 1)
    good = _hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not _hmac.compare_digest(sig, good):
        return None
    try:
        import base64
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return None
    if int(data.get("e") or 0) < time.time():
        return None
    return str(data.get("u") or "")


CURRENT_USER = None
CURRENT_NS = "default"

# prefixes that need a logged-in tenant
_REQUIRE_USER = ("/api/order", "/api/cart", "/api/accounts", "/api/addresses",
                 "/api/refer", "/api/wallet", "/api/orders", "/api/pay", "/api/admin")
_PUBLIC_PATHS = ("/", "/api", "/api/bootstrap", "/api/auth/login", "/api/auth/me",
                 "/api/auth/logout", "/api/auth/otp_send", "/api/auth/otp_verify",
                 "/api/auth/json_login", "/api/saas/plans")
_PUBLIC_PREFIXES = ("/api/search", "/api/product", "/api/price", "/api/variation",
                    "/api/suggest", "/api/geocode", "/api/offer")


def _current_user():
    return CURRENT_USER


def _plan(user):
    name = str((user or {}).get("plan") or "free")
    return PLANS.get(name, PLANS["free"])


def _used_today(user):
    today = time.strftime("%Y-%m-%d")
    used = user.get("used") or {}
    if used.get("date") != today:
        used = {"date": today, "count": 0}
    return used


def _trial_used(user):
    """Lifetime count of orders placed on the Free/trial plan."""
    return int((user or {}).get("trial_used") or 0)


def _plan_ok(user):
    plan = _plan(user)
    if not plan.get("orders") or plan["key"] == "proplus":
        return True, plan, None
    if plan.get("trial"):
        # Free trial: 10 free orders TOTAL (lifetime), not per-day.
        used = _trial_used(user)
        cap = TRIAL_FREE_ORDERS if "trial" in plan else plan["orders"]
        if used >= cap:
            return False, plan, {"error": "plan_limit", "limit": cap, "used": used,
                                 "trial": True, "message": f"Your 10 free trial orders are used up. Upgrade to keep ordering."}
        return True, plan, None
    used = _used_today(user)
    if used["count"] >= plan["orders"]:
        return False, plan, {"error": "plan_limit", "limit": plan["orders"], "used": used["count"]}
    return True, plan, None


def _charge_order(user):
    users = _load_users()
    u = users.get(user.get("username")) if user else None
    if not u:
        return
    if _plan(u).get("trial"):
        # Trial orders accumulate lifetime so the 10-free-order trial depletes.
        u["trial_used"] = _trial_used(u) + 1
    else:
        used = _used_today(u)
        used["count"] += 1
        u["used"] = {"date": used["date"], "count": used["count"]}
    _save_users(users)


def _user_devices(user):
    prefix = "u%s:" % int(user.get("id") or 0)
    return [ns for ns in DEVICES if ns.startswith(prefix)]


def _user_account_count(user):
    n = 0
    for ns in _user_devices(user):
        n += len(DEVICES[ns].get("accounts") or [])
    return n


def _auth_err():
    return {"error": "auth_required", "_status": 401,
            "message": "Please log in to continue."}


@app.middleware("http")
async def device_isolation_middleware(request: Request, call_next):
    global db, CURRENT_NS, CURRENT_USER
    path = request.url.path
    try:
        did = (request.headers.get("X-Device-ID") or "").strip() or "default"
    except Exception:
        did = "default"
    token = request.headers.get("X-Session", "") or request.headers.get("X-Tg-Init-Data", "")
    username = _verify_token(token)
    user = None
    if username:
        users = _ensure_admin()
        user = users.get(username)
        if user and not user.get("active"):
            user = None
        if user:
            user["last_seen"] = int(time.time())
    CURRENT_USER = user

    public = path in _PUBLIC_PATHS or path.startswith(_PUBLIC_PREFIXES)
    admin = path.startswith("/api/admin")
    gated = any(path.startswith(p) for p in _REQUIRE_USER)

    if admin:
        if not (user and user.get("role") == "admin"):
            ns = ("u%s:" % int(user.get("id") or 0) if user else "anon:") + did
            CURRENT_NS = ns
            db = DEVICES.setdefault(ns, _default_state())
            return JSONResponse(_auth_err(), status_code=401)
    elif gated and not public:
        if not user:
            ns = "anon:" + did
            CURRENT_NS = ns
            db = DEVICES.setdefault(ns, _default_state())
            return JSONResponse(_auth_err(), status_code=401)

    if user:
        # One-time tenant migration: give the FIRST logged-in admin a working
        # copy of any pre-SaaS device namespace that still holds accounts, so
        # existing saved sessions stay reachable under u{id}:{device}.
        if user.get("role") == "admin":
            try:
                for legacy in list(DEVICES.keys()):
                    if ":" not in legacy and (DEVICES[legacy].get("accounts") or []):
                        tns = "u%s:%s" % (int(user.get("id") or 0), legacy)
                        if tns not in DEVICES:
                            DEVICES[tns] = copy.deepcopy(DEVICES[legacy])
            except Exception:
                pass
        ns = "u%s:%s" % (int(user.get("id") or 0), did)
    else:
        ns = "anon:" + did
    CURRENT_NS = ns
    db = DEVICES.setdefault(ns, _default_state())
    response = await call_next(request)
    return response


def _device_id():
    ns = globals().get("CURRENT_NS") or "default"
    return (ns.rsplit(":", 1)[-1] or "default")



@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(BASE_DIR, "index.html"), headers={"Cache-Control": "no-store, no-cache, must-revalidate"})


@app.get("/api")
async def api_index():
    """API overview — lists every live endpoint running on this server."""
    routes = [
        {"path": r.path, "methods": sorted(r.methods) if getattr(r, "methods", None) else None}
        for r in app.routes
        if getattr(r, "path", "") and r.path.startswith("/api")
    ]
    return {
        "service": "Meesho Auto-Bot Web API",
        "version": "1.0",
        "live": True,
        "endpoints": routes,
        "usage": "All /api/* paths accept JSON. Full UI at GET / ; state reset at GET /clear",
    }


@app.get("/api/saas/plans")
async def api_saas_plans():
    """Public plan catalogue for the pricing/upgrade sheet."""
    return {"plans": list(PLANS.values())}


@app.post("/api/auth/login")
async def api_auth_login(data: dict = None):
    """SaaS login. Accepts either a username/password pair OR a pasted JSON
    credentials document. Returns a signed session token (use as X-Session)."""
    import hmac as _hmac
    data = data or {}
    users = _ensure_admin()
    username = str(data.get("username") or data.get("user") or "").strip()
    password = str(data.get("password") or data.get("pass") or "")
    u = users.get(username)
    if not u or not u.get("active"):
        return {"error": "bad_credentials", "message": "Unknown user or account is blocked."}
    if not password or not _hmac.compare_digest(str(u.get("password") or ""), password):
        return {"error": "bad_credentials", "message": "Wrong username or password."}
    u["last_seen"] = int(time.time())
    _save_users(users)
    return {"ok": True, "token": _issue_token(username),
            "user": {"username": username, "role": u.get("role"),
                     "plan": u.get("plan"), "id": u.get("id")}}


@app.get("/api/auth/me")
async def api_auth_me():
    u = _current_user()
    if not u:
        return {"authenticated": False}
    return _auth_me(u)


def _auth_me(u):
    users = _load_users()
    cu = users.get(u.get("username")) or u
    plan = _plan(cu)
    if plan.get("trial"):
        used = _trial_used(cu)
        cap = TRIAL_FREE_ORDERS
        left = max(0, cap - used)
        return {"authenticated": True,
                "user": {"username": cu["username"], "role": cu.get("role"), "plan": cu.get("plan"),
                         "devices": len(_user_devices(cu)), "accounts": _user_account_count(cu),
                         "id": cu.get("id")},
                "plan": plan, "used_trial": used, "trials_left": left, "used_today": 0,
                "orders_left": left, "trial": True}
    used = _used_today(cu)
    left = -1 if not plan.get("orders") or plan["key"] == "proplus" else max(0, plan["orders"] - used["count"])
    return {"authenticated": True,
            "user": {"username": cu["username"], "role": cu.get("role"), "plan": cu.get("plan"),
                     "devices": len(_user_devices(cu)), "accounts": _user_account_count(cu),
                     "id": cu.get("id")},
            "plan": plan, "used_today": used["count"], "orders_left": left}


@app.post("/api/auth/otp_send")
async def api_auth_otp_send(data: dict = None):
    """Gate login option 1 — real Meesho OTP (send step). No session needed; the
    verified number auto-provisions (or reuses) a tenant on verify."""
    data = data or {}
    phone = str(data.get("phone_number", "")).strip()[-10:]
    if not phone.isdigit() or len(phone) != 10:
        return {"ok": False, "error": "Enter a valid 10-digit number"}
    res = await meesho_request_otp(phone)
    if not res["ok"]:
        return {"ok": False, "phone": phone, "live": False,
                "error": res.get("error", "Could not send OTP")}
    return {"ok": True, "phone": phone, "request_id": res["request_id"],
            "instance_id": res["instance_id"], "live": True}


@app.post("/api/auth/otp_verify")
async def api_auth_otp_verify(data: dict = None, request: Request = None):
    """Verify the OTP, auto-provision the tenant keyed to the phone, link the
    freshly-verified Meesho account to this device, and return a session token."""
    data = data or {}
    phone = str(data.get("phone_number", "")).strip()[-10:]
    otp = str(data.get("otp", ""))
    request_id = data.get("request_id", "req_" + phone[-4:])
    instance_id = data.get("instance_id", "inst_fallback_live")
    res = await meesho_verify_otp(phone, otp, request_id, instance_id)
    if not res["ok"]:
        return {"ok": False, "live": res.get("live", False),
                "error": res.get("error", "Verification failed"),
                "wrong_otp": bool(res.get("wrong_otp"))}
    try:
        did = (request.headers.get("X-Device-ID") or "").strip() or "default"
    except Exception:
        did = "default"
    users = _load_users()
    un = phone
    user = users.get(un)
    if user and not user.get("active"):
        return {"ok": False, "live": res.get("live", False), "error": "blocked",
                "message": "This account is blocked by the shop."}
    if not user:
        nid = max([int(x.get("id") or 0) for x in users.values()] or [0]) + 1
        user = {"id": nid, "username": un, "password": uuid.uuid4().hex[:12],
                "role": "user", "plan": "free", "active": True,
                "created_at": int(time.time()), "last_seen": int(time.time()),
                "used": {"date": "", "count": 0}, "trial_used": 0}
        users[un] = user
        _save_users(users)
    token = _issue_token(un)
    # link the verified Meesho account into the user's device namespace
    ns = "u%s:%s" % (int(user["id"]), did)
    ust = DEVICES.setdefault(ns, _default_state())
    ust.setdefault("accounts", [])
    if res.get("live") and "is_new" in res:
        ust.setdefault("phone_status", {})[phone] = {
            "registered": (res.get("is_new") is False),
            "is_new": res.get("is_new"),
            "sign_up_date": res.get("sign_up_date"),
            "checked_at": time.time(),
        }
    acc = next((a for a in ust["accounts"] if str(a.get("mobile", "")) == phone), None)
    if acc:
        acc.update({
            "user_id": res.get("user_id", acc.get("user_id")),
            "xo": res.get("xo", acc.get("xo")),
            "instance_id": res.get("instance_id", acc.get("instance_id")),
            "cookies": res.get("cookies", acc.get("cookies")),
            "xo_exp": res.get("xo_exp", acc.get("xo_exp")),
        })
        ust["active_id"] = acc["id"]
    else:
        new_acc = {
            "id": str(uuid.uuid4().hex)[:8],
            "mobile": phone,
            "user_id": res.get("user_id"),
            "cookies": res.get("cookies"),
            "xo": res.get("xo"),
            "instance_id": res.get("instance_id"),
            "uo": None,
            "source": "otp",
            "order_placed": False,
            "is_first_order": bool(res.get("is_new")),
            "xo_exp": res.get("xo_exp", 1795000000),
        }
        if not ust.get("active_id"):
            ust["active_id"] = new_acc["id"]
        ust["accounts"].insert(0, new_acc)
        acc = new_acc
    _persist()
    return {"ok": True, "live": res.get("live", False), "token": token,
            "account": acc, **_auth_me(user)}


@app.post("/api/auth/logout")
async def api_auth_logout():
    # stateless sessions — the client simply discards the token
    return {"ok": True, "message": "Logged out."}


@app.post("/api/auth/import_account")
async def api_auth_import_account(data: dict = None):
    """JSON login: paste an exported Meesho-account JSON (one account dict or an
    array) to add it to your tenant. Requires a logged-in session."""
    users = _load_users()
    u = _current_user()
    if not u:
        return {"ok": False, "live": True, "error": "auth_required",
                "message": "Please log in before importing an account."}
    plan = _plan(u)
    data = data or {}
    docs = data.get("accounts") if isinstance(data.get("accounts"), list) else (
        data.get("account") or data)
    if isinstance(docs, dict):
        docs = [docs]
    if not isinstance(docs, list) or not docs:
        return {"ok": False, "live": True, "error": "bad_json",
                "message": "Paste a Meesho-account JSON (looks like {\"mobile\":\"90xxxxxxxx\", \"authorization\":\"...\"})."}
    added, errors = 0, []
    for acc in docs:
        if not isinstance(acc, dict) or not (acc.get("mobile") or acc.get("authorization")):
            errors.append("missing mobile/authorization")
            continue
        if plan["devices"] and _user_account_count(u) >= plan["devices"]:
            return {"ok": False, "live": True, "error": "plan_limit", "plan": plan,
                    "message": f"Account limit ({plan['devices']}) reached on your {plan['label']} plan — upgrade to add more."}
        if any(str(a.get("mobile")) == str(acc.get("mobile")) for a in db.get("accounts") or []):
            errors.append(f"{acc.get('mobile')} already added")
            continue
        clean = {k: v for k, v in acc.items()
                 if k in ("mobile", "user_id", "userName", "authorization", "instance_id",
                          "app_session_id", "app_user_id", "u_token", "xo", "shield_session_id",
                          "meesho_user_context", "app_user_location", "app_version", "app_version_code")}
        clean["name"] = clean.get("userName") or clean.get("name") or f"Account {acc.get('mobile')}"
        clean["is_first_order"] = bool(acc.get("is_first_order") or clean.get("is_first_order"))
        new_id = str(uuid.uuid4().hex)[:8]
        clean["id"] = new_id
        db.get("accounts") or db.setdefault("accounts", []).append(clean)
        if db.get("active_id") is None:
            db["active_id"] = new_id
        added += 1
    _persist()
    return {"ok": added > 0, "live": True, "added": added, "errors": errors,
            "message": f"Added {added} account(s)." if added else "No accounts imported."}


def _extract_xo_from_composite(value):
    """A Meesho export's xo/xo_token is a composite JWTs ('eyJ0eXBlIjoiY29tcG9zaXRl
    In0=.eyJqd3QiOiL...'). The raw header xo lives at inner['xo']; user_id and
    instance_id live inside the nested jwt. Return (raw_xo, user_id, instance_id)."""
    raw_xo = ""
    user_id = ""
    instance_id = ""
    value = str(value or "")
    try:
        parts = value.split(".")
        if len(parts) >= 2:
            import base64 as _b64
            
            inner = json.loads(_b64url_decode(parts[1]))
            if isinstance(inner, dict):
                raw_xo = str(inner.get("xo") or "")
                jwt = inner.get("jwt") or ""
                if jwt and jwt.count(".") == 2:
                    payload = json.loads(_b64url_decode(jwt.split(".")[1]))
                    if isinstance(payload, dict):
                        user_id = str(payload.get("https://meesho.com/user_id") or "")
                        instance_id = str(payload.get("https://meesho.com/instance_id") or "")
    except Exception:
        pass
    return raw_xo, user_id, instance_id


@app.post("/api/auth/json_login")
async def api_auth_json_login(data: dict = None, request: Request = None):
    """Gate login option 2 — paste an exported Meesho session JSON. This BOTH logs
    you in (auto-provisions/reuses an SaaS tenant keyed to the mobile) AND imports
    the account, so the shop is immediately usable."""
    data = data or {}
    docs = data.get("accounts") if isinstance(data.get("accounts"), list) else (
        data.get("account") or data)
    if isinstance(docs, dict):
        docs = [docs]
    if not isinstance(docs, list) or not docs:
        return {"ok": False, "live": True, "error": "bad_json",
                "message": "Paste a Meesho-account export JSON ({\"phone\":\"+9190...\", ...})."}
    acc = docs[0]
    if not isinstance(acc, dict):
        return {"ok": False, "live": True, "error": "bad_json", "message": "Invalid account JSON."}
    phone_raw = str(acc.get("phone") or acc.get("mobile") or acc.get("number") or "")
    phone = re.sub(r"\D", "", phone_raw)[-10:]
    if not phone.isdigit() or len(phone) != 10:
        return {"ok": False, "live": True, "error": "bad_phone",
                "message": "No valid 10-digit mobile found in the JSON."}
    xo_src = acc.get("xo") or acc.get("xo_token") or acc.get("authorization") or ""
    raw_xo, jwt_uid, jwt_inst = _extract_xo_from_composite(xo_src)
    # NOTE: Meesho cart/checkout calls must be authenticated with the FULL
    # composite JWT (this is what logged_in_headers() puts in the xo header and
    # what the real app stores — see the working otp-flow accounts). Storing only
    # the raw inner xo here made the account load but every real-cart operation
    # land in a throwaway session (add "succeeds", review shows an empty cart).
    composite_xo = str(xo_src or "")
    xo = composite_xo if "." in composite_xo else (raw_xo or composite_xo)
    instance_id = str(acc.get("instance_id") or acc.get("instance") or jwt_inst or "")
    user_id = str(acc.get("user_id") or acc.get("userId") or jwt_uid or "")
    if not (xo and user_id and instance_id):
        return {"ok": False, "live": True, "error": "incomplete",
                "message": "This JSON is missing a full session (xo + user_id + instance_id)."}
    try:
        did = (request.headers.get("X-Device-ID") or "").strip() or "default"
    except Exception:
        did = "default"
    users = _load_users()
    un = phone
    user = users.get(un)
    if user and not user.get("active"):
        return {"ok": False, "live": True, "error": "blocked",
                "message": "This account is blocked by the shop."}
    if not user:
        nid = max([int(x.get("id") or 0) for x in users.values()] or [0]) + 1
        user = {"id": nid, "username": un, "password": uuid.uuid4().hex[:12],
                "role": "user", "plan": "free", "active": True,
                "created_at": int(time.time()), "last_seen": int(time.time()),
                "used": {"date": "", "count": 0}, "trial_used": 0}
        users[un] = user
        _save_users(users)
    token = _issue_token(un)
    ns = "u%s:%s" % (int(user["id"]), did)
    ust = DEVICES.setdefault(ns, _default_state())
    ust.setdefault("accounts", [])
    existing = next((a for a in ust["accounts"] if str(a.get("mobile", "")) == phone), None)
    xo_exp = 1795000000
    try:
        parts = str(xo_src or "").split(".")
        if len(parts) == 2:
            
            inner = json.loads(_b64url_decode(parts[1]))
            jwt = (inner or {}).get("jwt") or ""
            if jwt and jwt.count(".") == 2:
                payload = json.loads(_b64url_decode(jwt.split(".")[1]))
                exp = (payload or {}).get("exp")
                if exp:
                    xo_exp = int(exp)
    except Exception:
        pass
    new_acc = {
        "id": str(uuid.uuid4().hex)[:8],
        "mobile": phone,
        "user_id": user_id,
        "xo": xo,
        "xo_raw": raw_xo or None,
        "instance_id": instance_id,
        "uo": None,
        "source": "json",
        "order_placed": False,
        "is_first_order": bool(acc.get("new_account") or acc.get("is_first_order") or
                               (acc.get("fod_anon") or {}).get("on")),
        "xo_exp": xo_exp,
        "ox": acc.get("ox") or acc.get("ox_token"),
        "otpless_token": acc.get("otpless_token"),
        "id_token": acc.get("id_token"),
        "gaid": acc.get("gaid"),
        "via": acc.get("via"),
    }
    if existing:
        prev = existing.get("id")
        new_acc["id"] = prev
        existing.update(new_acc)
        acc = existing
    else:
        ust["accounts"].insert(0, new_acc)
        acc = new_acc
    if not ust.get("active_id"):
        ust["active_id"] = acc["id"]
    else:
        ust["active_id"] = acc["id"]
    _persist()

    # Detect the account's REAL first-order-discount state from Meesho's own cart
    # review (result.user_meta.is_first_order is the server-side truth). A
    # JSON-imported account is usually freshly created and ALREADY has a FOD
    # present server-side, so we surface that real state instead of guessing or
    # rolling a fake offer — and we avoid fabricating a FOD for a returning buyer.
    fod = {"lookup": "skip", "is_first_order": bool(acc.get("is_first_order")), "offer": None}
    try:
        resp = await _account_real_fod(acc)
        if resp.get("ok"):
            fod = {
                "lookup": "live",
                "is_first_order": bool(resp.get("is_first_order")),
                "offer": resp.get("offer"),
                "message": resp.get("message"),
            }
            # Trust the live server check for eligibility
            acc["is_first_order"] = bool(resp.get("is_first_order"))
            acc["order_placed"] = not bool(resp.get("is_first_order"))
            if resp.get("offer"):
                bound = dict(resp["offer"])
                acc["bound_offer"] = bound
                acc["bucket"] = str(bound.get("bucket") or bound.get("text") or "")
                acc["bucket_text"] = bound.get("text", "") or bound.get("subtitle", "")
            acc["fod_lookup"] = fod
            _persist()
        else:
            fod = {"lookup": "error", "message": resp.get("message"),
                   "is_first_order": bool(acc.get("is_first_order")), "offer": None}
            acc["fod_lookup"] = fod
            _persist()
    except Exception as _e:
        acc.setdefault("fod_lookup",
                       {"lookup": "error", "message": f"{type(_e).__name__}: {_e}"})

    return {"ok": True, "live": True, "token": token,
            "account": acc, "imported_as": "saas+account", "fod": acc.get("fod_lookup"),
            **_auth_me(user)}


@app.get("/api/admin/users")
async def api_admin_users():
    u = _current_user()
    if not (u and u.get("role") == "admin"):
        return {"error": "admin_only", "_status": 401, "message": "Admins only."}
    users = _load_users()
    out = []
    for un in users.values():
        plan = _plan(un)
        used = _used_today(un)
        out.append({"username": un["username"], "role": un.get("role"), "plan": un.get("plan"),
                    "active": bool(un.get("active")), "created_at": un.get("created_at"),
                    "last_seen": un.get("last_seen"), "devices": len(_user_devices(un)),
                    "used_today": used["count"], "orders_limit": plan["orders"], "id": un.get("id")})
    return {"users": out}


@app.post("/api/admin/users")
async def api_admin_users_update(data: dict = None):
    u = _current_user()
    if not (u and u.get("role") == "admin"):
        return {"error": "admin_only", "message": "Admins only."}
    data = data or {}
    users = _load_users()
    un = str(data.get("username") or "")
    target = users.get(un)
    if not target:
        if data.get("password"):
            nid = max([int(x.get("id") or 0) for x in users.values()] or [0]) + 1
            users[un] = {"id": nid, "username": un, "password": str(data["password"]),
                         "role": data.get("role", "user"), "plan": data.get("plan", "free"),
                         "active": bool(data.get("active", True)), "created_at": int(time.time()),
                         "last_seen": 0, "used": {"date": "", "count": 0}, "trial_used": 0}
            _save_users(users)
            return {"ok": True, "message": f"{un} created."}
        return {"error": "not_found", "message": "Unknown user — include a password to create them."}
    if data.get("plan") in PLANS:
        target["plan"] = data["plan"]
    if data.get("active") is not None and str(data.get("username")) != os.getenv("ADMIN_USER", "admin"):
        target["active"] = bool(data["active"])
    if data.get("role") in ("admin", "user", "member"):
        target["role"] = data["role"]
    if data.get("password"):
        target["password"] = str(data["password"])
    users[un] = dict(target)
    _save_users(users)
    return {"ok": True, "message": f"{un} updated."}


@app.post("/api/order/status")
async def api_order_status(data: dict = None):
    """Pay/order update: refresh an order's live Meesho state + tell the UI
    whether it can be cancelled right now."""
    data = data or {}
    onum = str(data.get("order_num") or "")
    cs = None
    for o in db.get("orders") or []:
        if str(o.get("order_num")) == onum:
            cs = o.get("cart_session")
            break
    st = await _real_order_state(onum, cs)
    info = {"cancellable": False, "payment_pending": False, "state": st}
    if isinstance(st, dict):
        state = str(st.get("state") or "")
        status = str(st.get("status") or "").upper()
        info["payment_pending"] = state == "pending"
        info["expired"] = state == "failed"
        info["cancellable"] = state in ("ordered", "paid", "success", "completed", "confirmed")
        if info["expired"] or info["payment_pending"] or any(w in status for w in ("CANCEL", "RTO", "RETURN", "DELIVERED", "FAILED")):
            info["cancellable"] = False
    for o in db.get("orders") or []:
        if str(o.get("order_num")) == onum:
            o["cancellable"] = info["cancellable"]
    _persist()
    return {"ok": True, "order_num": onum, **info}


@app.get("/clear")
async def clear_everything():
    """Clear stale data for the CURRENT browser only (device-scoped, not global)."""
    ns = globals().get("CURRENT_NS") or "default"
    st = DEVICES.setdefault(ns, _default_state())
    st["orders"] = []
    st["cart"] = {"items": [], "total_quantity": 0, "effective_total": 0, "cart_session": "", "address": None}
    st["pending_binds"] = {}
    st["picked_offer"] = None
    _persist()
    html = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Resetting…</title></head><body>
<script>
localStorage.clear();
document.title = 'Cleared!';
document.body.innerHTML = '<h2 style="font-family:sans-serif;text-align:center;margin-top:40vh">All cleared — redirecting…</h2>';
setTimeout(function(){ window.location.href = '/'; }, 800);
</script></body></html>"""
    from starlette.responses import HTMLResponse
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


# ---------------- SESSION / ACCOUNTS ----------------
@app.get("/api/bootstrap")
async def api_bootstrap():
    return {"accounts": db["accounts"], "active_id": db["active_id"], "balance": 0, "per_order_price": 0}


@app.post("/api/accounts/select")
async def api_accounts_select(data: dict = None):
    req = data.get("account_id", 1) if data else 1
    acc = next((a for a in db["accounts"] if str(a.get("id")) == str(req)), None)
    db["active_id"] = acc["id"] if acc is not None else req
    # Cart context (session/address) is account-scoped on Meesho — clear any
    # stale address from another account so checkout never re-binds it.
    db["cart"]["address"] = {}
    db["cart"]["cart_session"] = ""
    _persist()
    return {"ok": True}


@app.get("/api/accounts/list")
async def api_accounts_list():
    return {"accounts": db["accounts"]}


@app.get("/api/accounts/order_status")
async def api_accounts_order_status():
    return {"statuses": {str(a["id"]): a.get("order_placed", False) for a in db["accounts"]}}


@app.post("/api/accounts/refresh")
async def api_accounts_refresh(data: dict):
    acct_id = data.get("account_id")
    for a in db["accounts"]:
        if a.get("id") == acct_id or str(a.get("id")) == str(acct_id):
            a["xo_exp"] = 1795000000 + 86400
            return {"ok": True, "account_id": a["id"], "message": "Session refreshed"}
    return {"ok": False, "error": "Account not found"}


@app.post("/api/accounts/refresh_bulk")
async def api_accounts_refresh_bulk(data: dict = None):
    for a in db["accounts"]:
        a["xo_exp"] = 1795000000 + 86400
    return {"ok": True, "refreshed": len(db["accounts"])}


@app.post("/api/accounts/delete")
async def api_accounts_delete(data: dict = None):
    ids = (data or {}).get("ids") or []
    db["accounts"] = [a for a in db["accounts"] if a.get("id") not in ids]
    if db["active_id"] in ids:
        db["active_id"] = db["accounts"][0]["id"] if db["accounts"] else None
    _persist()
    return {"ok": True, "deleted": len(ids)}


@app.post("/api/account/export_file")
async def api_account_export_file():
    return {"ok": True, "message": "Session file exported"}


@app.get("/api/accounts/export_files")
async def api_accounts_export_files():
    return {"ok": True, "exported": len(db["accounts"])}


@app.post("/api/accounts/login_otp")
async def api_accounts_login_otp(data: dict):
    phone = str(data.get("phone_number", "")).strip()[-10:]
    if not phone.isdigit() or len(phone) != 10:
        return {"ok": False, "error": "Enter a valid 10-digit number"}
    _u = _current_user()
    _pl = _plan(_u)
    if _pl["devices"] and _user_account_count(_u) >= _pl["devices"]:
        return {"ok": False, "live": True, "error": "plan_limit", "plan": _pl,
                "message": f"Account limit ({_pl['devices']}) reached on your {_pl['label']} plan — upgrade to add more."}
    res = await meesho_request_otp(phone)
    if not res["ok"]:
        return {"ok": False, "phone": phone, "live": False,
                "error": res.get("error", "Could not send OTP")}
    return {"ok": True, "phone": phone, "request_id": res["request_id"],
            "instance_id": res["instance_id"], "live": True}


@app.post("/api/accounts/login_verify")
async def api_accounts_login_verify(data: dict):
    phone = str(data.get("phone_number", "")).strip()[-10:]
    otp = str(data.get("otp", ""))
    request_id = data.get("request_id", "req_" + phone[-4:])
    instance_id = data.get("instance_id", "inst_fallback_live")
    res = await meesho_verify_otp(phone, otp, request_id, instance_id)
    if res["ok"]:
        record_phone_truth(phone, res)
        existing = next((a for a in db["accounts"] if str(a.get("mobile", "")) == phone), None)
        if existing:
            existing.update({
                "user_id": res.get("user_id", existing.get("user_id")),
                "xo": res.get("xo", existing.get("xo")),
                "instance_id": res.get("instance_id", existing.get("instance_id")),
                "cookies": res.get("cookies", existing.get("cookies")),
                "xo_exp": res.get("xo_exp", existing.get("xo_exp")),
            })
            db["active_id"] = existing["id"]
            _persist()
            return {"ok": True, "account": existing, "live": res.get("live", False)}
        new_acc = {
            "id": len(db["accounts"]) + 1,
            "mobile": phone,
            "user_id": res.get("user_id"),
            "cookies": res.get("cookies"),
            "xo": res.get("xo"),
            "instance_id": res.get("instance_id"),
            "uo": None,
            "source": "otp",
            "order_placed": False,
            "is_first_order": bool(res.get("is_new")),
            "xo_exp": res.get("xo_exp", 1795000000),
        }
        db["accounts"].append(new_acc)
        db["active_id"] = new_acc["id"]
        _persist()
        return {"ok": True, "account": new_acc, "live": res.get("live", False)}
    return {"ok": False, "error": res.get("error", "Verification failed")}


# ---------------- SEARCH / PRODUCT ----------------
@app.post("/api/search")
async def api_search(data: dict = None):
    data = data or {}
    query = str(data.get("query") or "").strip()
    if not query:
        return {"catalogs": [], "cursor": None, "search_session_id": None}
    offset = int(data.get("offset") or 0)
    cursor = data.get("cursor")
    session_id = data.get("search_session_id")
    result = await meesho_search(query, cursor=cursor, offset=offset, session_id=session_id)
    return result or {"catalogs": [], "cursor": None, "search_session_id": None}


@app.post("/api/search/suggest")
async def api_search_suggest(data: dict = None):
    prefix = str((data or {}).get("prefix") or "").strip()[:40]
    if not prefix:
        return []
    items = await meesho_search_suggest(prefix)
    return items or []


@app.get("/api/product")
async def api_product_detail(product_id: int):
    live = await meesho_product(product_id)
    if live:
        return live
    return {"ok": False, "error": "Could not load this product's live data — try again.", "live": True}


@app.get("/api/product/{product_id}")
async def api_product_detail_path(product_id: int):
    return await api_product_detail(product_id)


@app.post("/api/product/by_link")
async def api_product_by_link(data: dict):
    link = str(data.get("link", "")).strip()
    m = re.search(r"product/(\d+)", link)
    if not m:
        return {"error": "bad_link", "message": "That link doesn't look like a Meesho product link"}
    live = await meesho_product(int(m.group(1)))
    if live:
        return live
    return {"error": "live_fail", "ok": False,
            "message": "Could not load this product's live data — try again."}


@app.post("/api/variation")
async def api_variation(data: dict = None):
    data = data or {}
    pid = int(data.get("product_id") or 0)
    prod = await _live_product(pid)
    if not prod:
        return {"ok": False, "error": "Could not load this product's live data — try again.", "live": True}
    offer = active_offer()
    final, sav, pct = apply_fod(prod.get("list_price") or prod["price"], offer)
    return {"ok": True, "price": final, "mrp": prod["mrp"], "list_price": prod.get("list_price") or prod["price"],
            "discount_text": "Free Order" if pct == 100 else (sav if pct else prod.get("discount_text", "OFF")),
            "discount": sav, "in_stock": prod.get("in_stock", True), "cod_available": True,
            "price_type_id": prod.get("price_type_id"),
            "fod": {"saved_text": sav, "pct": pct, "offer": (offer.get("title") or "FREE ORDER") if offer else None, "final_price": final},
            "shipping": {"charges": 0, "estimated_delivery": {"title": "Free Delivery", "date": "Within 3 Days"}}}


@app.post("/api/price/check")
async def api_price_check(data: dict = None):
    data = data or {}
    link = str(data.get("link", ""))
    m = re.search(r"product/(\d+)", link)
    pid = int(m.group(1)) if m else 0
    prod = await _live_product(pid)
    if not prod:
        return {"ok": False, "error": "Could not load this product's live data — try again.", "live": True}
    offer = active_offer()
    final, sav, pct = apply_fod(prod.get("list_price") or prod["price"], offer)
    return {
        "ok": True,
        "product_id": pid,
        "name": prod["name"],
        "price": final,
        "mrp": prod["mrp"],
        "list_price": prod.get("list_price") or prod["price"],
        "discount": "Free Order" if pct == 100 else sav,
        "fod": {"saved_text": sav, "pct": pct, "offer": offer.get("title") or "FREE ORDER", "final_price": final},
        "accounts": [{"id": a["id"], "mobile": a.get("mobile", ""), "price": final, "mrp": prod["mrp"]} for a in db["accounts"]] or [{"id": 1, "mobile": "New Delhi", "price": final, "mrp": prod["mrp"]}],
        "best_price": final,
        "best_mrp": prod["mrp"],
    }


# ---------------- CART ----------------
def _cart_items_totals(items):
    total_mrp = 0.0
    total_pay = 0.0
    qty = 0
    for it in items or []:
        mrp = float(it.get("mrp") or 0)
        price = float(it.get("price") or 0) or mrp
        q = int(it.get("quantity") or 1) or 1
        total_mrp += mrp * q
        total_pay += price * q
        qty += q
    return total_mrp, total_pay, qty


async def _real_cart_review():
    """Load the REAL cart for the active saved account via api/8.0/cart
    (POST, context atc_payment_summary — captured from the real app).
    Returns a mapped payload (items / totals / address / cart_session) or None."""
    h = _active_headers()
    if not h:
        return None
    acc = _active_account()
    uid = acc["user_id"]
    cs = db["cart"].get("cart_session") or ""
    body = {
        "context": "review", "identifier": "buy_now", "cart_session": cs,
        "dest_pin": None, "address_id": None, "customerAmount": None, "payment_modes": None,
        "replaceable": None, "item": None, "payment_instrument": None, "bank_offers": None,
        "filter_products": True, "is_self_pickup": None, "self_pickup_address": None,
        "is_emi": None, "user_id": uid,
    }
    resp = await meesho_request("POST", "https://prod.meeshoapi.com/api/9.0/cart",
                                json=body, headers=h, timeout=25)
    if not resp or resp.status_code != 200:
        return None
    d = _as_json(resp)
    if not (d and d.get("success") and d.get("cart_session") and d.get("result")):
        return None
    cs_new = d["cart_session"]
    res = d["result"]
    items = []
    for s in res.get("splits") or []:
        sup = s.get("supplier") or {}
        for p in s.get("products") or []:
            imgs = p.get("images") or []
            pu = p.get("price_unbundling") or {}
            raw_ro = pu.get("return_options") or []
            # Map return_options to frontend-friendly shape; replace <amount> placeholder
            ret_opts = []
            for ro in raw_ro:
                if not isinstance(ro, dict) or not ro.get("price_type_id"):
                    continue
                desc = (ro.get("offer") or {}).get("description") or ""
                amt_val = (ro.get("offer") or {}).get("amount")
                if "<amount>" in desc and amt_val is not None:
                    desc = desc.replace("<amount>", str(amt_val))
                ret_opts.append({
                    "price_type_id": ro["price_type_id"],
                    "add_on_price": ro.get("price"),
                    "name": ro.get("name", ""),
                    "description": desc,
                })
            items.append({
                "identifier": p.get("identifier"),
                "product_id": p.get("product_id"),
                "catalog_id": (p.get("catalog") or {}).get("id") if isinstance(p.get("catalog"), dict) else None,
                "name": p.get("name"),
                "supplier_id": sup.get("id"),
                "supplier_name": sup.get("name"),
                "variation_id": p.get("variation_id"),
                "variation": p.get("variation"),
                "quantity": int(p.get("quantity") or 1),
                "max_quantity": int(p.get("max_quantity") or 10),
                "price": p.get("price"),
                "mrp": p.get("mrp"),
                "original_price": p.get("original_price"),
                "image": imgs[0] if imgs else None,
                "images": imgs,
                "price_type_id": pu.get("selected_price_type_id"),
                "discount_text": p.get("discount_text"),
                "return_options": ret_opts,
                "return_header": pu.get("return_type_explaination_header", "Easy Returns"),
            })
    addr = res.get("address") or {}
    merged_addr = _map_meesho_addr(addr)
    if merged_addr:
        db["cart"]["address"] = merged_addr
    else:
        db["cart"]["address"] = {}
    total_mrp, total_pay, qty = _cart_items_totals(items)
    fod = None
    if (res.get("user_meta") or {}).get("is_first_order"):
        fod = {"title": "Free", "text": "Free", "offer": "First Order"}
    db["cart"]["cart_session"] = cs_new
    db["cart"]["live"] = True
    return {
        "live": True,
        "cart_session": cs_new,
        "items": items,
        "total_quantity": res.get("total_quantity", qty),
        "effective_total": res.get("effective_total", total_pay),
        "effective_total_for_upi_plugin": res.get("effective_total_for_upi_plugin") or (res.get("effective_total") or 0),
        "effective_total_with_ppd": res.get("effective_total_with_ppd"),
        "effective_amount_all_payment": res.get("effective_amount_all_payment"),
        "effective_total_for_bnpl": res.get("effective_total_for_bnpl"),
        "total_mrp": round(total_mrp, 2),
        "before_fod": round(total_pay, 2),
        "address": merged_addr,
        "user_meta": res.get("user_meta"),
        "price_break_up": [
            {
                "display_name": (r.get("display_name") or r.get("type") or ""),
                "type": (r.get("type") or r.get("display_name") or ""),
                "value": r.get("value"),
                "details": r.get("details"),
                "disclaimer": r.get("disclaimer"),
            }
            for r in (res.get("price_break_up") or [])
            if isinstance(r, dict)
        ],
        "fod": fod,
    }


async def _account_real_fod(acc=None):
    """Determine the active account's REAL first-order-discount state directly
    from Meesho's cart review response (result.user_meta.is_first_order is the
    server-side source of truth — a JSON-imported account created with a FOD
    present reports is_first_order=true, a returning buyer reports false).

    Returns a dict:
      {"ok": True, "is_first_order": bool, "live": True,
       "offer": {...}|None, "message": ...}
    or {"ok": False, "live": False, "message": ...} when the check can't run."""
    try:
        h = _active_headers()
        if not h:
            return {"ok": False, "live": False, "message": "No logged-in account session."}
        a = acc or _active_account()
        if not a:
            return {"ok": False, "live": False, "message": "No active account."}
        uid = a["user_id"]
        review = await _real_cart_review()
        um = {}
        offer = None
        if review:
            um = review.get("user_meta") or {}
        else:
            # Review can fail on an empty cart; still hit the raw cart API to read
            # user_meta so eligibility is reported even with nothing in the bag.
            body = {
                "context": "review", "identifier": "buy_now", "cart_session": "",
                "dest_pin": None, "address_id": None, "customerAmount": None,
                "payment_modes": None, "replaceable": None, "item": None,
                "payment_instrument": None, "bank_offers": None, "filter_products": True,
                "is_self_pickup": None, "self_pickup_address": None, "is_emi": None,
                "user_id": uid,
            }
            resp = await meesho_request("POST", "https://prod.meeshoapi.com/api/9.0/cart",
                                        json=body, headers=h, timeout=25)
            if resp and resp.status_code == 200:
                d = _as_json(resp)
                res = (d or {}).get("result") or {}
                um = res.get("user_meta") or {}
                fod_offer = (res or {}).get("surgical_first_order_discount_v3") or {}
                if fod_offer.get("enabled") and fod_offer.get("offer"):
                    offer = {
                        "title": (fod_offer["offer"].get("offer_title") or "Upto"),
                        "text": (fod_offer["offer"].get("offer_text") or ""),
                        "subtitle": (fod_offer["offer"].get("offer_subtitle") or "on 1st order"),
                        "bucket": fod_offer["offer"].get("max_offer_value"),
                    }
        first = bool(um.get("is_first_order"))
        return {
            "ok": True,
            "live": True,
            "is_first_order": first,
            "offer": offer,
            "message": ("First-order discount available" if first
                        else "Account is not a first-time buyer — no FOD."),
        }
    except Exception as e:
        return {"ok": False, "live": False, "message": f"{type(e).__name__}: {e}"}

    """Update quantity of an existing real cart line. Meesho's actual pattern
    is cart/remove + cart/add (no cart/update in the new HAR). We remove the
    old item and re-add it with the new quantity."""
    h = _active_headers()
    if not h:
        return None
    acc = _active_account()
    cs = db["cart"].get("cart_session") or ""
    identifier = item.get("identifier")
    if not identifier:
        return {"success": False, "error": "no identifier"}
    uid = acc["user_id"]

    # Step 1: Remove the item
    remove_body = {
        "identifier": "default", "cart_session": cs,
        "items": [identifier], "context": "atc_cart_v2", "user_id": uid,
    }
    resp = await meesho_request("POST", "https://prod.meeshoapi.com/api/1.0/cart/remove",
                                json=remove_body, headers=h, timeout=20)
    d = _as_json(resp) if resp else {}
    if not resp or resp.status_code != 200 or not (d and d.get("success")):
        return {"success": False, "error": "remove failed", "detail": d}
    cs = d.get("cart_session") or cs
    db["cart"]["cart_session"] = cs
    if quantity <= 0:
        d["cart_session"] = cs
        return d

    # Step 2: Re-add with new quantity
    add_body = {
        "context": "pdp", "identifier": "buy_now", "cart_session": cs, "replaceable": False,
        "items": [{
            "identifier": "buy_now", "product_id": int(item.get("product_id") or 0),
            "supplier_id": int(item.get("supplier_id")) if item.get("supplier_id") else None,
            "variation_id": item.get("variation_id"), "variation": item.get("variation"),
            "quantity": int(quantity),
            "selected_price_type_id": price_type_id or item.get("price_type_id") or "premium_return_price",
            "client_metadata": None,
        }],
        "address_id": None, "user_id": uid,
    }
    resp2 = await meesho_request("POST", "https://prod.meeshoapi.com/api/1.0/cart/add",
                                 json=add_body, headers=h, timeout=25)
    d2 = _as_json(resp2) if resp2 else {}
    if not resp2 or resp2.status_code != 200 or not (d2 and d2.get("success")):
        return {"success": False, "error": "re-add failed", "detail": d2}
    new_cs = d2.get("cart_session") or cs
    db["cart"]["cart_session"] = new_cs
    d2["cart_session"] = new_cs
    # Update item identifier from the re-add response
    new_id = None
    for s in (d2.get("result", {}).get("splits") or []):
        for p in (s.get("products") or []):
            if int(p.get("product_id") or 0) == int(item.get("product_id") or 0):
                new_id = p.get("identifier")
                break
        if new_id:
            break
    if new_id:
        item["identifier"] = new_id
    return d2


async def _real_cart_remove(item, cart_session=None):
    """Remove an item identifier from the REAL Meesho cart via api/1.0/cart/remove.
    Returns the raw response dict (with cart_session) or a failure dict."""
    h = _active_headers()
    if not h:
        return None
    acc = _active_account()
    identifier = item.get("identifier") if isinstance(item, dict) else item
    if not identifier:
        return {"success": False, "error": "no identifier"}
    cs = cart_session or db["cart"].get("cart_session") or ""
    body = {
        "identifier": "buy_now", "cart_session": cs,
        "items": [identifier], "context": "atc_cart_v2", "user_id": acc["user_id"],
    }
    resp = await meesho_request("POST", "https://prod.meeshoapi.com/api/1.0/cart/remove",
                                json=body, headers=h, timeout=20)
    d = _as_json(resp) if resp else {}
    if not resp or resp.status_code != 200 or not (d and d.get("success")):
        return {"success": False, "error": "remove failed", "detail": d, "status": getattr(resp, "status_code", None)}
    new_cs = d.get("cart_session") or cs
    db["cart"]["cart_session"] = new_cs
    d["cart_session"] = new_cs
    return d


async def _real_cart_add(product_id, supplier_id, variation_id, variation, quantity, selected_price_type_id=None):
    """Add an item to the REAL cart via api/1.0/cart/add. Returns the raw response dict.
    Premium return price type is the app's default; a basic_return_price fallback
    is tried when premium is rejected with CART_OOS."""
    h = _active_headers()
    if not h:
        return None
    acc = _active_account()
    body = {
        "context": "pdp", "identifier": "buy_now",
        "cart_session": db["cart"].get("cart_session"),
        "replaceable": False,
        "items": [{
            "identifier": "buy_now",
            "product_id": int(product_id),
            "supplier_id": int(supplier_id) if supplier_id else None,
            "variation_id": variation_id,
            "variation": variation,
            "quantity": int(quantity),
            "selected_price_type_id": selected_price_type_id or "premium_return_price",
            "client_metadata": None,
        }],
        "address_id": None,
        "user_id": acc["user_id"],
    }
    resp = await meesho_request("POST", "https://prod.meeshoapi.com/api/1.0/cart/add",
                                json=body, headers=h, timeout=25)
    if not resp:
        return {"ok": False, "error": "no response"}
    try:
        d = resp.json()
    except Exception:
        d = {}
    d["_status"] = resp.status_code
    ecode = (d.get("error") or {}).get("code") if isinstance(d.get("error"), dict) else None
    if not d.get("success") and ecode == "CART_OOS" and d.get("_status") == 200:
        body["items"][0]["selected_price_type_id"] = "basic_return_price"
        resp2 = await meesho_request("POST", "https://prod.meeshoapi.com/api/1.0/cart/add",
                                     json=body, headers=h, timeout=25)
        if resp2:
            try:
                d = resp2.json()
            except Exception:
                d = {}
            d["_status"] = resp2.status_code
    return d


async def _real_cart_add_many(items, cart_session=""):
    """Add the FULL bag in ONE api/1.0/cart/add call. Items are added with the
    'buy_now' identifier so they land in the checkout/review cart that
    /api/9.0/cart review + /api/4.0/preorders read — 'default' populates a
    different (shared-tab) cart that review never sees (add "succeeds" but the
    review returns an empty cart -> CART_NOT_FOUND on bind). Returns the raw
    response dict."""
    h = _active_headers()
    if not h:
        return {"ok": False, "error": "no_account"}
    acc = _active_account()
    its = []
    for li in items:
        its.append({
            "identifier": "buy_now",
            "product_id": int(li.get("product_id") or 0),
            "supplier_id": int(li.get("supplier_id")) if li.get("supplier_id") else None,
            "variation_id": li.get("variation_id"),
            "variation": li.get("variation") or "Free Size",
            "quantity": int(li.get("quantity") or 1),
            "selected_price_type_id": li.get("price_type_id") or "premium_return_price",
            "client_metadata": None,
        })
    body = {
        "context": "pdp", "identifier": "buy_now", "cart_session": cart_session or "",
        "replaceable": False, "items": its, "address_id": None, "user_id": acc["user_id"],
    }
    resp = await meesho_request("POST", "https://prod.meeshoapi.com/api/1.0/cart/add",
                                json=body, headers=h, timeout=30)
    d = _as_json(resp) if resp else {}
    if not resp or resp.status_code != 200 or not (d and d.get("success")):
        return {"ok": False, "error": "add_many failed", "detail": d,
                "status": getattr(resp, "status_code", None)}
    new_cs = d.get("cart_session") or cart_session or ""
    db["cart"]["cart_session"] = new_cs
    d["cart_session"] = new_cs
    return d


async def _reconcile_real_cart(local_items=None):
    """Make the REAL Meesho cart (of the ACTIVE account) match the LOCAL device
    cart so the Meesho app on the phone shows exactly what the bot is ordering.
    Runs on every cart mutation. Never raises — sync problems are reported in
    the response, they can't break the local UI."""
    try:
        h = _active_headers()
        if not h:
            return {"ok": False, "error": "no_account", "message": "No active account"}
        local = local_items if local_items is not None else (db["cart"].get("items") or [])
        want = {}
        for it in local:
            pid = it.get("product_id")
            if pid:
                want[(str(pid), str(it.get("variation_id") or ""))] = it
        review = await _real_cart_review()
        if review is None:
            return {"ok": False, "error": "cart_review_failed",
                    "message": "Could not load the live Meesho cart for sync."}
        cs = review.get("cart_session") or db["cart"].get("cart_session") or ""
        db["cart"]["cart_session"] = cs
        have = {}
        for ri in review.get("items") or []:
            have[(str(ri.get("product_id")), str(ri.get("variation_id") or ""))] = ri
        stats = {"added": 0, "removed": 0}
        if len(want) == len(have):
            same = True
            for k, li in want.items():
                ri = have.get(k)
                if ri is None or int(ri.get("quantity") or 1) != int(li.get("quantity") or 1):
                    same = False
                    break
            if same:
                review2 = await _real_cart_review()
                if review2:
                    db["cart"]["cart_session"] = review2.get("cart_session") or cs
                _persist()
                return {**stats, "ok": True, "cart_session": db["cart"].get("cart_session") or cs,
                        "message": "Cart synced with Meesho"}
        # Clear the real cart entirely, then push the whole bag in ONE call so
        # multiple items actually survive (per-item buy_now replaces the cart).
        for k, ri in have.items():
            if ri.get("identifier"):
                r = await _real_cart_remove(ri, db["cart"].get("cart_session") or cs)
                if r and r.get("success"):
                    stats["removed"] += 1
        if want:
            res = await _real_cart_add_many(list(want.values()), db["cart"].get("cart_session") or cs)
            if not (res and res.get("success")):
                return {"ok": False, "error": "sync_error",
                        "message": "Could not push the multi-item cart to Meesho.", "detail": res}
            stats["added"] = len(want)
        review2 = await _real_cart_review()
        if review2:
            db["cart"]["cart_session"] = review2.get("cart_session") or cs
        _persist()
        return {**stats, "ok": True, "cart_session": db["cart"].get("cart_session") or cs,
                "message": "Cart synced with Meesho"}
    except Exception as e:
        return {"ok": False, "error": "sync_error", "message": f"{type(e).__name__}: {e}"}


async def _real_paymentinfo(cart_session, amount):
    """Fetch the real paymentinfo (UPI-prepaid price) for a cart session.
    Returns (paymentinfo_dict, order_total, upi_amount)."""
    h = _active_headers()
    if not h:
        return None, None, None
    acc = _active_account()
    body = {
        "context": "payment_summary", "identifier": "buy_now", "cart_session": cart_session,
        "dest_pin": None, "address_id": None, "customerAmount": None,
        "payment_modes": ["upi_qr"], "replaceable": None, "item": None,
        "payment_instrument": None, "bank_offers": None, "filter_products": None,
        "is_self_pickup": None, "self_pickup_address": None, "is_emi": None, "user_id": acc["user_id"],
    }
    resp = await meesho_request("POST", "https://prod.meeshoapi.com/api/1.0/cart/paymentinfo",
                                json=body, headers=h, timeout=25)
    if not resp or resp.status_code != 200:
        return None, None, None
    d = _as_json(resp)
    if not (d and d.get("success") and d.get("result")):
        return None, None, None
    res = d["result"]

    def _num(v):
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            try:
                return float(v.replace(",", ""))
            except Exception:
                return None
        return None

    order_total = _num(res.get("effective_total")) or _num(amount) or 0.0
    upi_amount = _num(res.get("effective_total_for_upi_plugin")) or order_total
    return d, order_total, upi_amount


def _dump_preorders(tag, **obj):
    """Persist preorders traffic for debugging (never raises)."""
    try:
        import os as _os
        with open(_os.path.join(STATE_DIR, "preorders_debug.log"), "a", encoding="utf-8") as f:
            f.write(f"\n===== {tag} {datetime.datetime.now()} =====\n")
            for k, v in obj.items():
                f.write(f"--- {k} ---\n")
                f.write(json.dumps(v, ensure_ascii=False, default=str)[:12000] + "\n")
    except Exception:
        pass


_CART_CHANGED_CODES = {
    "CART_UPDATED", "TOTAL_CHANGED", "CART_CHANGED", "CART_MODIFIED",
    "CART_INELIGIBLE", "CART_ITEM_UNAVAILABLE", "CART_EMPTY", "CART_OOS",
    "ITEM_OOS", "PRICE_CHANGED",
}


async def _fresh_checkout_state(need_paymentinfo=True):
    """Run review -> bind address -> (paymentinfo) with FULLY fresh sessions and
    amounts. Returns dict(cs, addr, amt, order_total, upi_amount) or None.
    Meesho rotates cart_sessions constantly; this always returns the NEWEST one
    (including any session rotated inside the paymentinfo response).

    need_paymentinfo=False (COD orders): skip the UPI paymentinfo call. Calling
    paymentinfo with payment_modes=['upi_qr'] immediately before a COD preorders
    makes Meesho mark the cart "updated" and reject the COD order with
    CART_INELIGIBLE on some accounts; COD only needs the bind/review total."""
    review = await _real_cart_review()
    if not review or not review.get("cart_session"):
        _dump_preorders("fresh_checkout", review=review)
        return None
    cs = review["cart_session"]
    addr = review.get("address") or {}
    if not addr.get("id") and addr.get("address_id"):
        addr["id"] = addr["address_id"]
    if not (addr and addr.get("id")):
        acc_addrs = await _fetch_meesho_addresses()
        if not acc_addrs:
            acc_addrs = _account_addresses()
        if not acc_addrs:
            _dump_preorders("fresh_checkout_no_addr", review=review)
            return None
        addr = acc_addrs[0]
    bound_cs, bound_result = await _bind_address_to_cart(cs, addr["id"], addr.get("pin"))
    if not bound_cs:
        _dump_preorders("fresh_checkout_bind_fail", cs=cs, addr=addr)
        return None
    cs = bound_cs
    if bound_result and bound_result.get("address_id"):
        addr["id"] = bound_result["address_id"]
    order_total = upi_amount = None
    if need_paymentinfo:
        d, order_total, upi_amount = await _real_paymentinfo(cs, review.get("effective_total"))
        if order_total is None or order_total <= 0:
            _dump_preorders("fresh_checkout_zero_amt", cs=cs, order_total=order_total, d=d)
            return None
        newcs = None
        if isinstance(d, dict):
            res = d.get("result") if isinstance(d.get("result"), dict) else {}
            newcs = d.get("cart_session") or res.get("cart_session")
        if newcs and str(newcs) != str(cs):
            cs = newcs
    else:
        order_total = (bound_result or {}).get("effective_total") or review.get("effective_total")
        if order_total is None or order_total <= 0:
            _dump_preorders("fresh_checkout_cod_zero_amt", cs=cs, bound_result=bound_result,
                            review_eff=review.get("effective_total"))
            return None
    return {"cs": cs, "addr": addr, "amt": int(round(order_total)),
            "order_total": order_total, "upi_amount": upi_amount,
            "items": review.get("items") or [], "total_quantity": review.get("total_quantity"),
            "effective_total": review.get("effective_total"), "fod": review.get("fod")}


async def _send_preorders(body, headers, uid):
    """POST /api/4.0/preorders with traffic dump + ONE automatic self-healing
    retry when Meesho says the cart changed (rotated session / price moved).
    Returns (ok, d, final_cs, status)."""
    def _send(cs, amt):
        b = dict(body)
        b["cart_session"] = cs
        b["customer_amount"] = amt
        b["user_id"] = uid
        _dump_preorders("preorders_request", body=b)
        return meesho_request("POST", "https://prod.meeshoapi.com/api/4.0/preorders",
                              json=b, headers=headers, timeout=30)

    d = {}
    final_cs = body.get("cart_session")
    final_amt = body.get("customer_amount")
    for attempt in (1, 2):
        cs = body["cart_session"]
        amt = body["customer_amount"]
        if attempt == 2:
            fresh = await _fresh_checkout_state()
            if not fresh:
                _dump_preorders("preorders_retry_no_fresh")
                return False, d, None, None, None
            cs, amt = fresh["cs"], fresh["amt"]
        resp = await _send(cs, amt)
        final_cs, final_amt = cs, amt
        if not resp:
            _dump_preorders("preorders_response", status=None)
            return False, d, final_cs, None, final_amt
        _dump_preorders("preorders_response", status=resp.status_code)
        try:
            d = resp.json()
        except Exception:
            d = {}
        _dump_preorders("preorders_json", d=d)
        if isinstance(d, dict) and d.get("order_num"):
            return True, d, final_cs, resp.status_code, final_amt
        code = ""
        e = d.get("error") if isinstance(d, dict) else None
        if isinstance(e, dict):
            code = str(e.get("code") or e.get("error_code") or "")
        if attempt == 1 and code and code.upper() in _CART_CHANGED_CODES:
            _dump_preorders("preorders_cart_changed_retry", code=code, cs=cs)
            continue
        return False, d, final_cs, resp.status_code, final_amt
    return False, d, final_cs, None, final_amt


_PAID_WORDS = ("paid", "confirmed", "success", "successful", "paid_success", "completed", "done")
_PENDING_WORDS = ("ordered", "pending", "init", "processing", "awaiting", "created", "unpaid",
                  "in_progress", "not_paid", "")
_FAILED_WORDS = ("failed", "cancelled", "cancelling", "expired", "rejected", "declined")


def _dict_has_paid_flag(d):
    """Scan a Meesho response dict for any explicit 'payment is done' marker.
    Only strong, definite signals count — never guess."""
    if not isinstance(d, dict):
        return False
    paid_keys = ("payment_status", "payment_state", "paid_status", "pay_status",
                 "is_paid", "paid", "payment_done", "txn_status")
    for k, v in d.items():
        if isinstance(v, dict):
            if _dict_has_paid_flag(v):
                return True
            continue
        kl = str(k).lower()
        vl = str(v).lower()
        if kl in paid_keys and vl in ("paid", "success", "successful", "done", "true", "1", "yes", "completed"):
            return True
    return False


async def _order_detail_says_paid(order_num):
    """Cross-check the real order state via api/3.0/user/order-details (and the
    order list). A paid online order flips to STATUS_ID_ORDERED (real-world
    verified); an unpaid one stays awaiting-payment; an expired/unpaid preorder
    flips to STATUS_ID_CANCELLED. Returns:
      "paid"      -> definitely paid + placed
      "not_paid"  -> still awaiting payment (or COD)
      "cancelled" -> Meesho cancelled/preorder-expired
      None        -> unknown"""
    try:
        h = _active_headers()
        if not h:
            return None
        acc = _active_account()
        sub = str(order_num) + "_1"
        resp = await meesho_request(
            "POST", "https://prod.meeshoapi.com/api/3.0/user/order-details",
            json={"order_num": str(order_num), "sub_order_num": sub,
                  "user_id": acc["user_id"]}, headers=h, timeout=15)
        if resp and resp.status_code == 200:
            d = _as_json(resp)
            if isinstance(d, dict):
                st = str(d.get("order_status") or "").upper()
                pay = d.get("payment_details") or {}
                mode = str((pay or {}).get("final_payment_mode") or "").upper()
                if "COD" in mode or "CASH" in mode:
                    return "not_paid"
                if any(w in st for w in ("CANCELLED", "CANCEL", "REFUNDED", "RTO")):
                    return "cancelled"
                if st and any(w in st for w in ("ORDERED", "CONFIRMED", "ACCEPTED", "PLACED")):
                    return "paid"
        resp2 = await meesho_request(
            "POST", "https://prod.meeshoapi.com/api/3.0/user/orders",
            json={"limit": 10, "cursor": None, "query": None,
                  "filters": {"sub_order_status": [0], "sub_order_created": None},
                  "user_id": acc["user_id"]}, headers=h, timeout=15)
        if resp2 and resp2.status_code == 200:
            d2 = _as_json(resp2)
            if isinstance(d2, dict):
                for i in d2.get("sub_order_list") or []:
                    if str(i.get("order_num")) == str(order_num):
                        sst = str(i.get("sub_order_status") or "").upper()
                        pm = i.get("payment_details") or {}
                        mode = str(pm.get("final_payment_mode") or "").upper()
                        if "COD" in mode or "CASH" in mode:
                            return "not_paid"
                        if any(w in sst for w in ("CANCELLED", "CANCEL", "REFUNDED", "RTO")):
                            return "cancelled"
                        if any(w in sst for w in ("ORDERED", "CONFIRMED", "ACCEPTED", "PLACED")):
                            return "paid"
                        return "not_paid"
        return None
    except Exception:
        return None


async def _real_order_state(order_num, cart_session=None):
    """Ask the REAL Meesho for an order's current payment state.

    Uses api/1.0/preorders/payments/status — the endpoint the real app calls
    after creating an order to confirm it landed. Returns {"state": "confirmed"|"pending"|"failed",
    "status": str, "live": True} or None.

    HAR entry 242 confirms the request shape:
      {"pre_order_id":-1, "is_selling_to_customer":False, "order_num":"...",
       "retry_in_sec":0, "cart_session":"...", "user_id":...}
    and the right-after-creation response: {"status":"ordered","retry_in_sec":0}.
    "ordered" is the AWAITING-PAYMENT state — it must NEVER be treated as paid.
    Only explicit paid signals confirm; otherwise we cross-check order-details."""
    h = _active_headers()
    if not h or not order_num:
        return None
    acc = _active_account()
    cs = cart_session or db["cart"].get("cart_session") or ""
    body = {
        "pre_order_id": -1, "is_selling_to_customer": False,
        "order_num": str(order_num), "retry_in_sec": 0,
        "cart_session": cs, "user_id": acc["user_id"],
    }
    try:
        resp = await meesho_request("POST", "https://prod.meeshoapi.com/api/1.0/preorders/payments/status",
                                    json=body, headers=h, timeout=25)
        if resp and resp.status_code == 200:
            d = _as_json(resp)
            if isinstance(d, dict):
                st = str(d.get("status") or "").lower()
                if st in _PAID_WORDS or _dict_has_paid_flag(d):
                    return {"state": "confirmed", "status": d.get("status"), "live": True}
                if st in _FAILED_WORDS:
                    return {"state": "failed", "status": d.get("status"), "live": True}
                # pending family (incl. "ordered"): cross-check order status once
                od = await _order_detail_says_paid(order_num)
                if od == "paid":
                    return {"state": "confirmed", "status": d.get("status"), "live": True}
                if od == "cancelled":
                    return {"state": "failed", "status": d.get("status") or "cancelled", "live": True}
                if st in _PENDING_WORDS or not st:
                     return {"state": "pending", "status": d.get("status"), "live": True}
                return {"state": "unknown", "status": d.get("status") or "UNKNOWN", "live": True}
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# UNIVERSAL PAYMENT CHECK
# ---------------------------------------------------------------------------
# Ground truth captured from the real Meesho app HAR (logs.juspay.in ... .har).
#
# After creating a UPI QR order via /api/4.0/preorders the app does NOT treat
# the order as paid. It polls these live payment-state endpoints:
#
#   A) GET /api/v3/payments/{JUSPAY_ORDER_ID}/status?sync=true   (HAR #243-246)
#        -> {"success":true,"status":"SUCCESS"}   payment received
#        -> {"success":true,"status":"PENDING"}   still awaiting payment
#        -> {"success":true,"status":"FAILURE"}   payment failed / expired
#      {JUSPAY_ORDER_ID} is the JUSPAY order_id inside the preorders
#      qr_transaction_params.payload.order_id (e.g. "NKJ6OZGFBWQFZFBGTZDQ"),
#      NOT the Meesho order_num.
#
#   B) POST /api/1.0/preorders/payments/status  (HAR #242)
#        -> {"status":"ordered"}  awaiting-payment state, NOT paid
#      + cross-check /api/3.0/user/order-details -> STATUS_ID_* (HAR #112/181)
#
# A UPI order is only CONFIRMED when A returns status SUCCESS (or order-details
# shows a terminal placed/CANCELLED state). "ordered"/"ORDERED" from the
# preorders status call is the PRE-payment state and must never be escalated to
# "paid" on its own.
# ---------------------------------------------------------------------------

_V3_PAID = ("SUCCESS", "SUCCESSFUL", "CHARGED", "PAID", "CHARGED_SUCCESS", "AUTHORIZED")
_V3_PENDING = ("PENDING", "INITIATED", "STARTED", "PROCESSING", "ORDERED", "CREATED", "AWAITING", "")
_V3_FAILED = ("FAILURE", "FAILED", "CANCELLED", "CANCELED", "EXPIRE", "EXPIRED", "DECLINED", "REJECTED", "UNAUTHORIZED")


def _v3_state(status):
    if not status:
        return "pending"
    s = str(status).upper()
    if any(w in s for w in _V3_FAILED):
        return "failed"
    if any(w in s for w in _V3_PAID):
        return "confirmed"
    if any(w in s for w in _V3_PENDING):
        return "pending"
    return "unknown"


def _find_juspay_order_id(order):
    """Extract the JUSPAY order_id (the /api/v3/payments/... identifier) from a
    stored order's txn payload. Prefers txn.order_id that looks like a JUSPAY id."""
    if not isinstance(order, dict):
        return ""
    txn = order.get("txn") or {}
    if isinstance(txn, str):
        try:
            txn = json.loads(txn)
        except Exception:
            txn = {}
    if isinstance(txn, dict):
        oid = txn.get("order_id") or txn.get("juspay_order_id") or txn.get("request_id")
        if oid:
            return str(oid)
    return str(order.get("juspay_order_id") or order.get("qr_order_id") or "")


async def _v3_payment_status(juspay_order_id):
    """GET /api/v3/payments/{id}/status?sync=true — the real app's live payment
    check. Returns a dict {"status":..., "success":..., "live":bool, "raw":...}
    or None on network failure."""
    if not juspay_order_id:
        return None
    h = _active_headers()
    if not h:
        return None
    try:
        resp = await meesho_request(
            "GET",
            f"https://prod.meeshoapi.com/api/v3/payments/{juspay_order_id}/status",
            headers=h, params={"sync": "true"}, timeout=15)
        if resp and resp.status_code == 200:
            d = _as_json(resp)
            if isinstance(d, dict):
                return {"status": d.get("status"), "success": bool(d.get("success")),
                        "live": True, "raw": d}
        return {"live": False, "raw": None} if resp is None else None
    except Exception:
        return None


async def _universal_payment_check(order):
    """Authoritative live payment check for an order, using exactly the endpoints
    the real Meesho app polls after creating a UPI QR order. Stateless — reads the
    current state fresh from Meesho each call.

    Returns {"state":"confirmed"|"pending"|"failed"|"unknown", "source":...,
             "status":..., "live":bool, "detail":...}.
       confirmed -> payment actually received (order placed)
       pending   -> awaiting payment (QR shown, not paid yet)
       failed    -> payment failed / order cancelled / expired ("merchant dead")
    """
    if not isinstance(order, dict):
        return {"state": "unknown", "source": "none", "status": "", "live": False}
    acc = _active_account()
    uid = acc["user_id"] if acc else None
    onum = order.get("order_num")
    mode = str(order.get("payment_mode") or order.get("mode") or "").upper()

    # 1) JUSPAY v3 status (the #1 authority for online payment) — HAR #243-246
    jid = _find_juspay_order_id(order)
    if jid:
        v3 = await _v3_payment_status(jid)
        if v3 and v3.get("live"):
            state = _v3_state(v3.get("status"))
            if state != "unknown":
                return {"state": state, "source": "v3_payments_status",
                        "status": v3.get("status"), "live": True, "detail": v3.get("raw")}

    # 2) preorders/payments/status + order-details cross-check (HAR #242/#112)
    rstate = await _real_order_state(onum) if onum else None
    if rstate and rstate.get("live"):
        return {"state": rstate["state"], "source": "real_order_state",
                "status": rstate.get("status"), "live": True}

    # 3) If this is COD / cash, it is placed without payment.
    if "COD" in mode or "CASH" in mode or mode in ("COD",):
        return {"state": "confirmed", "source": "mode_cod", "status": "Order Placed", "live": True}

    return {"state": "unknown", "source": "none", "status": "", "live": False}


def _map_meesho_addr(addr):
    """Normalize a raw Meesho address dict to the bot's stored shape."""
    if not isinstance(addr, dict) or not addr.get("id"):
        return None
    coords = addr.get("coordinates") or {}
    if isinstance(coords, dict):
        lat = coords.get("latitude")
        lng = coords.get("longitude")
    else:
        lat = addr.get("latitude")
        lng = addr.get("longitude")
    return {
        "id": addr.get("id"),
        "user_id": addr.get("userId"),
        "name": addr.get("name"),
        "mobile": str(addr.get("mobile") or ""),
        "alternative_mobile": str(addr.get("alternative_mobile") or ""),
        "pin": addr.get("pin"),
        "city": addr.get("city"),
        "state": addr.get("state"),
        "address_line_1": addr.get("address_line_1"),
        "address_line_2": addr.get("address_line_2"),
        "landmark": addr.get("landmark"),
        "address_type": addr.get("address_type"),
        "coordinates": coords if isinstance(coords, dict) else {},
        "latitude": lat,
        "longitude": lng,
        "pin_serviceable": addr.get("pin_serviceable", True),
        "valid": addr.get("valid"),
        "estimated_delivery_date": addr.get("estimated_delivery_date"),
        "location": addr.get("location"),
    }


async def _fetch_meesho_addresses():
    """Fetch real address list from Meesho GET /api/3.0/addresses (ACTIVE account).
    Non-empty responses replace the account's stored book. Empty/error responses
    NEVER wipe the book — they fall back to the last known addresses for this
    account, so a flaky mobile network can't erase the book mid-order."""
    h = _active_headers()
    if not h:
        return []
    acc = _active_account()
    uid = acc["user_id"]
    try:
        resp = await meesho_request(
            "GET",
            "https://prod.meeshoapi.com/api/3.0/addresses?offset=0&limit=50&check_pin=true"
            "&context=cart&cart_identifier=buy_now&user_id={}".format(uid),
            headers=h, timeout=15,
        )
        if resp and resp.status_code == 200:
            d = _as_json(resp)
            if isinstance(d, dict) and isinstance(d.get("addresses"), list):
                mapped = [_map_meesho_addr(a) for a in d["addresses"] if isinstance(a, dict)]
                mapped = [m for m in mapped if m]
                if mapped:
                    _set_account_addresses(mapped)
                    return mapped
    except Exception:
        pass
    return _account_addresses()


async def _bind_address_to_cart(cart_session, address_id, dest_pin=None):
    """Bind an address to the cart session via POST /api/1.0/cart/location.
    Returns (bound_cart_session, review_dict) or (None, None) on failure.
    The bound session is what paymentinfo/preorders actually need."""
    h = _active_headers()
    if not h:
        return None, None
    acc = _active_account()
    body = {
        "context": "review", "identifier": "buy_now",
        "cart_session": cart_session or "",
        "dest_pin": dest_pin, "address_id": int(address_id),
        "customerAmount": None, "payment_modes": None,
        "replaceable": None, "item": None,
        "payment_instrument": None, "bank_offers": None,
        "filter_products": None, "is_self_pickup": None,
        "self_pickup_address": None, "is_emi": None,
        "user_id": acc["user_id"],
    }
    try:
        resp = await meesho_request(
            "POST", "https://prod.meeshoapi.com/api/1.0/cart/location",
            json=body, headers=h, timeout=20,
        )
        if resp and resp.status_code == 200:
            d = _as_json(resp)
            if isinstance(d, dict) and d.get("success"):
                new_cs = d.get("cart_session") or cart_session
                return new_cs, d.get("result")
    except Exception:
        pass
    return None, None


def _upi_intent_uri(order_num, amount, tr=None):
    """Real UPI URI per Meesho's captured juspay intent template. tr should be
    the juspay order_id when available so the payment reconciles on Meesho's side."""
    try:
        amt = f"{float(amount):.2f}"
    except Exception:
        amt = "0.00"
    ref = tr or f"meesho{order_num}1"
    return (f"upi://pay?tr={ref}&pa=MEESHOONLINEPG@ybl&mc=5262"
            f"&pn=MEESHO%20TECHNOLOGIES%20PRIVATE%20LIMITED&am={amt}&cu=INR&mode=04&purpose=00")


def _cart_recompute(force_items=None):
    offer = active_offer()
    items = force_items if force_items is not None else db["cart"].get("items") or []
    total_mrp = 0.0
    total_pay = 0.0
    qty = 0
    for it in items:
        mrp = float(it.get("mrp") or 0)
        price = float(it.get("price") or 0) or mrp
        q = int(it.get("quantity") or 1) or 1
        total_mrp += mrp * q
        total_pay += price * q
        qty += q
    # apply a REAL first-order offer only when the account is genuinely eligible
    final, savings, pct = apply_fod(total_pay, offer)
    if offer and pct and final < total_pay:
        savings_total = total_mrp - final
        fod = {"saved_text": savings, "pct": pct, "offer": offer.get("title") or "FREE ORDER", "final_price": round(final, 2)}
    else:
        final, savings, pct = total_pay, "No Discount", 0
        savings_total = 0.0
        fod = None
    db["cart"].update({
        "items": items,
        "total_quantity": qty,
        "effective_total": round(final, 2),
        "effective_online": round(final, 2),
        "total_mrp": round(total_mrp, 2),
        "before_fod": round(total_pay, 2),
        "fod_saved": round(savings_total, 2),
        "fod": fod,
        "price_break_up": [
            {"label": "Total MRP", "value": round(total_mrp, 2)},
            {"label": "Product discount", "value": round(total_mrp - total_pay, 2), "negative": True},
            {"label": "Shipping", "value": 0},
            {"label": "Total payable", "value": round(final, 2), "grand": True},
        ],
    })
    return db["cart"]


@app.get("/api/cart")
async def api_get_cart():
    # Device isolation: return LOCAL cart (per-device), not the shared Meesho cart
    _cart_recompute()
    return db["cart"]


@app.post("/api/cart/add")
async def api_cart_add(data: dict = None):
    data = data or {}
    pid = int(data.get("product_id") or 0)
    h = _active_headers()
    if not h:
        return {"ok": False, "live": True,
                "error": "No saved account session (faah). Log in first — OTP path at /api/accounts/login_otp."}
    prod = await _live_product(pid)
    if not prod:
        return {"ok": False, "live": True, "error": "Could not load this product's live data — try again."}
    if not prod.get("supplier_id"):
        return {"ok": False, "live": True, "error": "This product has no live seller on Meesho — pick another item."}
    variation = str(data.get("variation") or "Free Size")
    var_id = prod.get("variation_id")
    for s in prod.get("sizes") or []:
        if str(s.get("name") or "").strip().lower() == variation.strip().lower():
            var_id = s.get("variation_id")
            variation = str(s.get("name") or variation)
            break
    if var_id is None:
        return {"ok": False, "live": True, "error": f"Variation '{variation}' unknown for this product."}
    quantity = max(1, int(data.get("quantity") or 1))
    ptype = str(data.get("price_type_id") or prod.get("price_type_id") or "premium_return_price")
    # LOCAL add — store in device cart, don't hit Meesho API yet
    imgs = prod.get("images") or []
    item = {
        "identifier": f"{pid}_{var_id}",
        "product_id": pid,
        "supplier_id": prod.get("supplier_id"),
        "variation_id": var_id,
        "variation": variation,
        "quantity": quantity,
        "max_quantity": int(prod.get("max_quantity") or 10),
        "price": prod.get("list_price") or prod.get("price"),
        "mrp": prod.get("mrp"),
        "original_price": prod.get("original_price"),
        "name": prod.get("name"),
        "image": imgs[0] if imgs else None,
        "images": imgs,
        "price_type_id": ptype,
        "discount_text": prod.get("discount_text"),
        "return_options": [],
        "return_header": "Easy Returns",
        "catalog_id": prod.get("catalog_id"),
    }
    # Merge: if same product+variation already in cart, increment qty
    existing = None
    for it in db["cart"]["items"]:
        if it.get("product_id") == pid and it.get("variation_id") == var_id:
            existing = it
            break
    if existing:
        existing["quantity"] = min(existing.get("max_quantity", 10), existing["quantity"] + quantity)
    else:
        db["cart"]["items"].append(item)
    _cart_recompute(db["cart"]["items"])
    _persist()
    sync = await _reconcile_real_cart(db["cart"]["items"])
    db["cart"]["sync"] = sync
    return {
        "items": db["cart"]["items"],
        "total_quantity": db["cart"]["total_quantity"],
        "effective_total": db["cart"]["effective_total"],
        "fod": None,
        "cart_session": db["cart"].get("cart_session", ""),
        "live": False,
        "sync": sync,
    }


@app.post("/api/cart/update")
async def api_cart_update(data: dict = None):
    data = data or {}
    it = data.get("item") or {}
    pid = int(it.get("product_id") or data.get("product_id") or 0)
    qty = int(it.get("quantity", 1))
    # Update the LOCAL cart, then push the same change to the real Meesho cart.
    for x in db["cart"].get("items") or []:
        if x.get("identifier") == it.get("identifier") or int(x.get("product_id") or 0) == pid:
            if it.get("quantity") is not None:
                x["quantity"] = max(0, int(it["quantity"]))
            if it.get("variation"):
                x["variation"] = it["variation"]
    db["cart"]["items"] = [x for x in db["cart"].get("items") or [] if x.get("quantity", 0) > 0]
    _cart_recompute(db["cart"]["items"])
    _persist()
    sync = await _reconcile_real_cart(db["cart"]["items"])
    db["cart"]["sync"] = sync
    out = dict(db["cart"])
    out["sync"] = sync
    return out


@app.post("/api/cart/sync")
async def api_cart_sync(data: dict = None):
    """Explicitly push the local cart to the real Meesho cart (for the active
    account) so the Meesho app on the phone reflects the bot's cart."""
    sync = await _reconcile_real_cart(None)
    db["cart"]["sync"] = sync
    out = dict(db["cart"])
    out["sync"] = sync
    return out


@app.post("/api/cart/location")
async def api_cart_location(data: dict = None):
    data = data or {}
    addr = _account_address_by_id(data.get("address_id")) or {}
    db["cart"]["address"] = addr
    _persist()
    return {**db["cart"], "ok": bool(addr.get("id")), "address": addr}


# ---------------- ADDRESSES ----------------
@app.get("/api/addresses")
async def api_get_addresses():
    real = await _fetch_meesho_addresses()
    if real:
        return {"addresses": real, "default": real[0]}
    book = _account_addresses()
    if book:
        return {"addresses": book, "default": book[0]}
    return {"addresses": [], "default": None}


@app.get("/api/geocode")
async def api_geocode(q: Optional[str] = None, lat: Optional[float] = None, lng: Optional[float] = None):
    return {"results": [{"formatted": "Connaught Place, New Delhi - 110001", "city": "New Delhi", "state": "Delhi", "area": "Connaught Place", "pin": "110001", "lat": 28.6315, "lng": 77.2167}]}


@app.post("/api/addresses/create")
async def api_addresses_create(data: dict):
    """Create a REAL address on Meesho for the active account via
    POST /api/2.0/addresses (request shape captured from the real app).
    Without this call, a logged-in account with no saved address can never
    complete checkout — the old code only appended to the local db, and any
    address_id sent to /api/4.0/preorders got rejected with a generic 500."""
    data = data or {}
    h = _active_headers()
    if not h:
        return {"ok": False, "live": True, "error": "no_account",
                "message": "No saved account session. Log in first."}
    acc = _active_account()
    coords = data.get("coordinates") or {}
    if not isinstance(coords, dict):
        coords = {}
    body = {
        "alternative_mobile": str(data.get("alternative_mobile") or "").strip() or None,
        "address_type": data.get("address_type", "Home"),
        "city": data.get("city", ""),
        "mobile": str(data.get("mobile", "")),
        "coordinates": {
            "latitude": str(coords.get("latitude") or data.get("lat") or "0"),
            "longitude": str(coords.get("longitude") or data.get("lng") or "0"),
            "accuracy": str(coords.get("accuracy") or data.get("accuracy") or "41"),
        },
        "pin": str(data.get("pin", "")),
        "name": data.get("name", ""),
        "address_line_1": data.get("address_line_1", ""),
        "address_line_2": data.get("address_line_2", ""),
        "state": data.get("state", ""),
        "id": 0,
        "landmark": data.get("landmark", ""),
        "country_id": 1,
        "user_id": acc["user_id"],
    }
    try:
        resp = await meesho_request(
            "POST",
            "https://prod.meeshoapi.com/api/2.0/addresses?context=cart&cart_identifier=default",
            json=body, headers=h, timeout=25,
        )
    except Exception:
        return {"ok": False, "live": True, "error": "create_failed",
                "message": "Network error while creating the address on Meesho."}
    if not resp:
        return {"ok": False, "live": True, "error": "create_failed",
                "message": "Meesho did not respond to address creation."}
    d = _as_json(resp)
    if resp.status_code != 200 or not isinstance(d, dict) or not d.get("address"):
        err = ""
        if isinstance(d, dict):
            e = d.get("error") or {}
            if isinstance(e, dict):
                err = e.get("message") or e.get("code") or ""
            elif isinstance(e, str):
                err = e
        return {"ok": False, "live": True, "error": "rejected",
                "message": f"Meesho rejected the address ({resp.status_code}): {err}", "detail": d}
    a = _map_meesho_addr(d.get("address"))
    book = _account_addresses()
    if a:
        book = [x for x in book if x.get("id") != a["id"]]
        book.insert(0, a)
        _set_account_addresses(book)
        db["cart"]["address"] = a
    _persist()
    return {"ok": True, "id": a["id"] if a else None, "address": a}


@app.post("/api/addresses/update")
async def api_addresses_update(data: dict):
    """Update a REAL Meesho address via PUT /api/2.0/addresses/{id}."""
    data = data or {}
    h = _active_headers()
    if not h:
        return {"ok": False, "live": True, "error": "no_account",
                "message": "No saved account session. Log in first."}
    addr_id = int(data.get("address_id") or data.get("id") or 0)
    if not addr_id:
        return {"ok": False, "error": "Missing address_id"}
    body = {
        "alternative_mobile": str(data.get("alternative_mobile") or "").strip() or None,
        "pin": str(data.get("pin", "")),
        "address_type": data.get("address_type", "Home"),
        "city": data.get("city", ""),
        "name": data.get("name", ""),
        "address_line_1": data.get("address_line_1", ""),
        "mobile": str(data.get("mobile", "")),
        "address_line_2": data.get("address_line_2", ""),
        "state": data.get("state", ""),
        "id": addr_id,
        "landmark": data.get("landmark", ""),
        "country_id": 1,
    }
    try:
        resp = await meesho_request(
            "PUT",
            f"https://prod.meeshoapi.com/api/2.0/addresses/{addr_id}?context=cart&cart_identifier=buy_now",
            json=body, headers=h, timeout=25,
        )
    except Exception:
        return {"ok": False, "live": True, "error": "update_failed",
                "message": "Network error while updating the address on Meesho."}
    if not resp:
        return {"ok": False, "live": True, "error": "update_failed",
                "message": "Meesho did not respond to the address update."}
    d = _as_json(resp)
    if resp.status_code != 200 or not isinstance(d, dict) or not d.get("address"):
        err = ""
        if isinstance(d, dict):
            e = d.get("error") or {}
            if isinstance(e, dict):
                err = e.get("message") or e.get("code") or ""
            elif isinstance(e, str):
                err = e
        return {"ok": False, "live": True, "error": "rejected",
                "message": f"Meesho rejected the address update ({resp.status_code}): {err}", "detail": d}
    a = _map_meesho_addr(d.get("address"))
    if a:
        book = _account_addresses()
        book = [a if (isinstance(x, dict) and x.get("id") == a["id"]) else x for x in book]
        if not any(isinstance(x, dict) and x.get("id") == a["id"] for x in book):
            book.insert(0, a)
        _set_account_addresses(book)
        db["cart"]["address"] = a
    _persist()
    return {"ok": True, "id": a["id"] if a else None, "address": a}


@app.post("/api/addresses/set_default")
async def api_addresses_set_default(data: dict = None):
    data = data or {}
    a = _account_address_by_id((data or {}).get("address_id") or (data or {}).get("id"))
    if not a and isinstance(data, dict) and data.get("name"):
        a = data  # frontend passes the whole address object
    if not a or not a.get("id"):
        book = _account_addresses()
        a = book[0] if book else {}
    if a and a.get("id"):
        db["cart"]["address"] = a
        db["default_address"] = a  # global source for 'copy to active'
        _persist()
    return {"ok": True, "address": a}


async def _create_address_on_active(src):
    """Create a REAL Meesho address on the ACTIVE account from a source address
    dict. Used by 'copy to active' so a brand-new account gets a working
    delivery address without retyping everything."""
    h = _active_headers()
    if not h or not src or not src.get("pin"):
        return {"ok": False, "error": "no_account", "message": "No usable source address."}
    acc = _active_account()
    body = {
        "alternative_mobile": None,
        "address_type": src.get("address_type") or "Home",
        "city": src.get("city") or "",
        "mobile": str(src.get("mobile") or acc.get("mobile") or ""),
        "coordinates": {
            "latitude": str((src.get("coordinates") or {}).get("latitude") or "0"),
            "longitude": str((src.get("coordinates") or {}).get("longitude") or "0"),
            "accuracy": str((src.get("coordinates") or {}).get("accuracy") or "41"),
        },
        "pin": str(src.get("pin") or ""),
        "name": src.get("name") or "My Address",
        "address_line_1": src.get("address_line_1") or src.get("line1") or "",
        "address_line_2": src.get("address_line_2") or src.get("line2") or "",
        "state": src.get("state") or "",
        "id": 0,
        "landmark": src.get("landmark") or "",
        "country_id": 1,
        "user_id": acc["user_id"],
    }
    try:
        resp = await meesho_request(
            "POST",
            "https://prod.meeshoapi.com/api/2.0/addresses?context=cart&cart_identifier=default",
            json=body, headers=h, timeout=25,
        )
    except Exception:
        return {"ok": False, "error": "create_failed", "message": "Network error creating the address."}
    if not resp:
        return {"ok": False, "error": "create_failed", "message": "Meesho did not respond."}
    d = _as_json(resp)
    if resp.status_code != 200 or not isinstance(d, dict) or not d.get("address"):
        e = d.get("error") or {}
        err = e.get("message") if isinstance(e, dict) else ""
        return {"ok": False, "error": "rejected",
                "message": f"Meesho rejected the address ({resp.status_code}): {err}", "detail": d}
    a = _map_meesho_addr(d.get("address"))
    book = _account_addresses()
    if a:
        book = [x for x in book if x.get("id") != a["id"]]
        book.insert(0, a)
        _set_account_addresses(book)
        db["cart"]["address"] = a
    _persist()
    return {"ok": True, "id": a["id"] if a else None, "address": a}


@app.post("/api/addresses/copy_to_active")
async def api_addresses_copy_to_active(data: dict = None):
    data = data or {}
    src = (data or {}).get("address") or db.get("default_address")
    if not src or not src.get("pin"):
        return {"ok": False, "live": True, "error": "no_default",
                "message": "Set a default address first (star one on the Addresses tab)."}
    return await _create_address_on_active(src)


@app.post("/api/addresses/random_update")
async def api_addresses_random_update():
    """Pick the account's best address and make it the cart's delivery address.
    No random junk is ever created on Meesho — randomization would pollute the
    real account."""
    a = _account_address_by_id()
    if not a:
        return {"ok": False, "live": True, "error": "no_address",
                "message": "This account has no saved address to use."}
    db["cart"]["address"] = a
    _persist()
    return {"ok": True, "used": a}


@app.post("/api/order/bind-address")
async def api_bind_address(data: dict = None):
    """Bind a Meesho address to the cart session. Must be called before
    paymentinfo/preorders for real order placement to work."""
    data = data or {}
    h = _active_headers()
    if not h:
        return {"ok": False, "live": True, "error": "no_account",
                "message": "No saved account session. Log in first."}
    addr_id = data.get("address_id")
    if not addr_id:
        return {"ok": False, "live": True, "error": "no_address_id",
                "message": "Provide an address_id to bind."}
    cs = db["cart"].get("cart_session") or ""
    addr_pin = None
    owned = _account_address_by_id(addr_id)
    if owned:
        addr_pin = owned.get("pin")
    bound_cs, bound_result = await _bind_address_to_cart(cs, addr_id, addr_pin)
    if not bound_cs:
        return {"ok": False, "live": True, "error": "bind_failed",
                "message": "Meesho rejected the address binding."}
    db["cart"]["cart_session"] = bound_cs
    if bound_result:
        db["cart"]["address"] = bound_result.get("address") or db["cart"].get("address") or {}
        db["cart"]["address"]["id"] = int(addr_id)
    _persist()
    return {"ok": True, "live": True, "cart_session": bound_cs,
            "result": bound_result, "message": "Address bound to cart session."}


async def _clear_cart_after_order(cart_session, items):
    """After a successful preorders call, remove all items from the server-side
    cart so it's truly empty. The real Meesho app does this implicitly; our bot
    must do it explicitly so the cart tab shows empty."""
    h = _active_headers()
    acc = _active_account()
    if h and acc and items:
        uid = acc["user_id"]
        for it in items:
            ident = it.get("identifier")
            if not ident:
                continue
            try:
                await meesho_request("POST", "https://prod.meeshoapi.com/api/1.0/cart/remove",
                                    json={"identifier": "buy_now", "cart_session": cart_session,
                                          "items": [ident], "context": "atc_cart_v2", "user_id": uid},
                                    headers=h, timeout=10)
            except Exception:
                pass
    db["cart"]["items"] = []
    db["cart"]["cart_session"] = ""
    db["cart"]["total_quantity"] = 0
    _persist()


# ---------------- ORDERS ----------------
@app.post("/api/order/prices")
async def api_order_prices(data: dict = None):
    data = data or {}
    addr = db["cart"]["address"] or _account_address_by_id() or None
    if not data.get("no_live"):
        # Ensure the local cart is actually present on the real Meesho cart first.
        # Otherwise a fresh/empty server cart makes review return effective_total=0
        # and the checkout shows cod=0 / online=0.
        local_items = db["cart"].get("items") or []
        if local_items:
            await _real_cart_add_many(local_items, db["cart"].get("cart_session") or "")
        review = await _real_cart_review()
        if review:
            cs = review.get("cart_session") or db["cart"].get("cart_session") or ""
            # paymentinfo gives the real UPI-prepaid price (effective_total_for_upi_plugin)
            _, order_total, upi_amount = await _real_paymentinfo(cs, review.get("effective_total"))
            cod = float(order_total or review.get("effective_total") or 0)
            # UPI discount comes from paymentinfo, not cart review.
            # RULE: COD must always be HIGHER than the UPI price (prepaid discount).
            online = None
            for src in (upi_amount, review.get("effective_total_for_upi_plugin")):
                v = float(src) if src is not None else None
                if v is not None and v >= 0 and v < cod:
                    online = v
                    break
            if online is None or online >= cod:
                # Fallback: apply a standard prepaid discount if we can't get the
                # real UPI price, so COD stays strictly higher than UPI.
                online = cod if cod <= 0 else max(0.0, cod - 1)
            fod = review.get("fod")
            return {"cod": cod, "online": online, "address": review.get("address") or addr,
                    "fod": fod, "total": cod, "total_mrp": float(review.get("total_mrp") or 0),
                    "fod_saved": 0.0 if not fod else max(0.0, cod - float((fod or {}).get("final_price") or cod))}
    tot = db["cart"].get("effective_total") or 0
    return {"cod": tot, "online": tot, "address": addr, "fod": db["cart"].get("fod"), "total": tot, "total_mrp": db["cart"].get("total_mrp") or 0, "fod_saved": db["cart"].get("fod_saved") or 0}


@app.post("/api/order/place_cod")
async def api_place_cod(data: dict = None):
    """REAL Cash-on-Delivery order via api/4.0/preorders (captured COD body:
    payment_method_type/method COD, no UPI fields, customer_amount == paymentinfo
    effective_total). The order lands in the real Meesho app instantly."""
    data = data or {}
    _usr = _current_user()
    _ok, _cp, _lim = _plan_ok(_usr)
    if not _ok:
        return {"ok": False, "live": True, "error": "plan_limit", "plan": _cp,
                "message": f"Daily order limit ({_lim['limit']}) reached on your {_cp['label']} plan."}
    h = _active_headers()
    if not h:
        return {"ok": False, "live": True, "error": "no_account",
                "message": "No saved account session (faah). Log in first."}
    acc = _active_account()
    uid = acc["user_id"]

    if not (db["cart"].get("items") or []):
        return {"ok": False, "live": True, "error": "empty_cart",
                "message": "Your cart is empty."}

    st = await _fresh_checkout_state(need_paymentinfo=False)
    if not st:
        return {"ok": False, "live": True, "error": "cart_review_failed",
                "message": "Could not load the live Meesho cart."}
    cs = st["cs"]
    addr = st["addr"]
    amt = st["amt"]
    db["cart"]["cart_session"] = cs
    db["cart"]["address"] = addr

    loc = data.get("accurate_location") or {
        "latitude": str(addr.get("lat") or addr.get("latitude") or "24.0814"),
        "accuracy": float(data.get("accuracy") or 92.9),
        "longitude": str(addr.get("lng") or addr.get("longitude") or "84.0506737"),
    }
    body = {
        "payment_method_type": "COD", "identifier": "buy_now", "payment_aggregator": None,
        "is_selling_to_customer": False, "cart_session": cs, "vpa": None,
        "address_id": int(addr["id"]), "direct_wallet_token": None,
        "customer_amount": amt, "upi_package_name": None, "payment_flow_type": None,
        "sender_id": -1, "accurate_location": loc, "card_token": None,
        "payment_provider": None, "processor_id": None, "payment_method": "COD",
        "enable_price_unbundling": True, "user_id": uid,
    }
    ok, d, final_cs, status, final_amt = await _send_preorders(body, h, uid)
    if final_cs:
        cs = final_cs
        db["cart"]["cart_session"] = cs
    amt = final_amt if final_amt is not None else amt
    if not ok:
        err = "order rejected"
        e = d.get("error") if isinstance(d, dict) else None
        if isinstance(e, dict):
            err = e.get("message") or e.get("title") or err
        return {"ok": False, "live": True, "error": "order_rejected",
                "message": f"Meesho rejected the COD order ({status}): {err}", "detail": d}

    order_num = str(d["order_num"])
    was_first = bool(acc.get("is_first_order"))
    if acc.get("is_first_order"):
        acc["is_first_order"] = False
        acc["order_placed"] = True
    it = (st["items"] or [{}])[0]
    order = {
        "order_num": order_num,
        "sub_order_num": f"{order_num}_1",
        "status_id": "STATUS_ID_ORDERED",
        "status_text": "Order Placed",
        "status_color": "#038D63",
        "quantity": st["total_quantity"] or 1,
        "size": it.get("variation", ""),
        "name": it.get("name"),
        "image": it.get("image"),
        "amount": amt,
        "payment_mode": "cod",
        "is_first_order": was_first,
        "auto_cancel": bool(db.get("auto_cancel_orders", True)),
        "device_id": _device_id(),
        "cart_session": cs,
        "created_at": int(time.time()),
    }
    db["orders"].insert(0, order)
    _persist()

    # Confirm the COD order landed on Meesho via payments/status (HAR entry 242)
    # For COD this returns {"status":"ordered"} immediately
    try:
        status_resp = await _real_order_state(order_num, cs)
        if status_resp and status_resp.get("state") == "failed":
            order["status_id"] = "STATUS_ID_CANCELLED"
            order["status_text"] = "Order Failed"
            order["status_color"] = "#E74C3C"
            _persist()
            return {"ok": False, "live": True, "error": "order_failed",
                    "message": "Meesho rejected this COD order after creation."}
    except Exception:
        pass

    # Clear cart after successful order
    await _clear_cart_after_order(cs, st["items"] or [])

    _charge_order(_usr)
    return {"ok": True, "live": True, "order_num": order_num, "total": amt,
            "message": "Order placed with Cash on Delivery — it's live in the Meesho app."}


@app.post("/api/order/pay_online")
async def api_order_pay_online(data: dict = None):
    data = data or {}
    _usr = _current_user()
    _ok, _cp, _lim = _plan_ok(_usr)
    if not _ok:
        return {"ok": False, "live": True, "error": "plan_limit", "plan": _cp,
                "message": f"Daily order limit ({_lim['limit']}) reached on your {_cp['label']} plan."}
    h = _active_headers()
    if not h:
        return {"ok": False, "live": True,
                "error": "no_account",
                "message": "No saved account session (faah). Log in first."}
    acc = _active_account()
    uid = acc["user_id"]

    # 0) SYNC local device cart to Meesho's real cart before checkout
    local_items = db["cart"].get("items") or []
    if not local_items:
        return {"ok": False, "live": True, "error": "empty_cart",
                "message": "Your cart is empty."}
    # Clear Meesho's real cart first
    existing = await _real_cart_review()
    if existing and existing.get("items"):
        for ei in existing["items"]:
            if ei.get("identifier") and existing.get("cart_session"):
                await _real_cart_remove(ei, existing["cart_session"])
    # Push the FULL local bag in one call so multiple items survive
    valid_items = [li for li in local_items
                   if li.get("product_id") and li.get("supplier_id") and li.get("variation_id")]
    if not valid_items:
        return {"ok": False, "live": True, "error": "empty_cart",
                "message": "No complete items in your cart."}
    add_result = await _real_cart_add_many(valid_items)
    if add_result and add_result.get("success"):
        res = add_result.get("result") or {}
        cs_new = add_result.get("cart_session")
        if cs_new:
            db["cart"]["cart_session"] = cs_new
        # Update local items with server-assigned identifiers/prices
        by_pid = {}
        for s in (res.get("splits") or []):
            for p in (s.get("products") or []):
                by_pid[int(p.get("product_id") or 0)] = p
        for li in valid_items:
            p = by_pid.get(int(li.get("product_id") or 0))
            if p:
                li["identifier"] = p.get("identifier") or li.get("identifier")
                li["price"] = p.get("price") or li.get("price")
                li["mrp"] = p.get("mrp") or li.get("mrp")

    # 1) REAL cart session + address via one fresh review->bind chain. We do NOT
    #    call paymentinfo before preorders: on some accounts the UPI payment_summary
    #    call (payment_modes=['upi_qr']) marks the bound cart "updated" and the
    #    follow-up preorders then rejects with CART_INELIGIBLE ("Your cart has been
    #    updated"). customer_amount for preorders MUST equal effective_total.
    st = await _fresh_checkout_state(need_paymentinfo=False)
    if not st:
        return {"ok": False, "live": True, "error": "cart_review_failed",
                "message": "Could not load the live Meesho cart."}
    cs = st["cs"]
    addr = st["addr"]
    amt = st["amt"]
    upi_amount = st["upi_amount"]
    db["cart"]["cart_session"] = cs
    db["cart"]["address"] = addr

    loc = data.get("accurate_location") or {
        "latitude": str(addr.get("lat") or addr.get("latitude") or "24.0814"),
        "accuracy": float(data.get("accuracy") or 92.9),
        "longitude": str(addr.get("lng") or addr.get("longitude") or "84.0506737"),
    }

    # 3) REAL order creation (UPI QR) -> real order_num + juspay transaction_params + QR image
    body = {
        "payment_method_type": "UPI", "identifier": "buy_now", "payment_aggregator": "JUSPAY",
        "is_selling_to_customer": False, "cart_session": cs, "vpa": None,
        "address_id": int(addr["id"]), "direct_wallet_token": None,
        "customer_amount": amt, "upi_package_name": "com.google.android.apps.nbu.paisa.user",
        "payment_flow_type": "qr", "sender_id": -1, "accurate_location": loc,
        "card_token": None, "payment_provider": "JUSPAY",
        "processor_id": "in.juspay.hyperapi", "payment_method": "UPI",
        "enable_price_unbundling": True, "user_id": uid,
    }
    ok, d, final_cs, status, final_amt = await _send_preorders(body, h, uid)
    if final_cs:
        cs = final_cs
        db["cart"]["cart_session"] = cs
    amt = final_amt if final_amt is not None else amt
    if not ok:
        err = "order rejected"
        e = d.get("error") if isinstance(d, dict) else None
        if isinstance(e, dict):
            err = e.get("message") or e.get("title") or err
        return {"ok": False, "live": True, "error": "order_rejected",
                "message": f"Meesho rejected the order ({status}): {err}", "detail": d}

    order_num = str(d["order_num"])
    upi_uri = ""
    package_name = "com.google.android.apps.nbu.paisa.user"
    txn = {}
    jtid = ""
    qr_base64 = ""
    # Extract from qr_transaction_params (real Meesho response) OR juspay_transaction_params
    tp = d.get("qr_transaction_params") or d.get("juspay_transaction_params") or d.get("transaction_params")
    if isinstance(tp, dict):
        payload = tp.get("payload") or {}
        order_id = payload.get("order_id") or ""
        txn = {
            "order_id": order_id,
            "client_auth_token": payload.get("client_auth_token"),
            "request_id": tp.get("request_id"),
            "action": payload.get("action"),
            "amount": amt,
            "currency": "INR",
        }
        if payload.get("pay_with_app"):
            package_name = payload.get("pay_with_app")
        jtid = order_id
        # Extract the real QR code image from Meesho's response.
        # The QR itself is the payment instruction returned by the API —
        # no UPI URI is fabricated when a real QR exists.
        qr_b64 = payload.get("qr_base64_string") or ""
        if qr_b64:
            qr_base64 = qr_b64
        if payload.get("upi_intent_url"):
            upi_uri = payload["upi_intent_url"]
    elif isinstance(tp, str):
        try:
            tpv = json.loads(tp)
            payload = tpv.get("payload") or {}
            ud = (payload.get("payment_details") or {}).get("data") or {}
            upi_uri = ud.get("upi", {}).get("intent_url") or ""
            package_name = ud.get("upi", {}).get("package_name") or package_name
            qr_b64 = payload.get("qr_base64_string") or ""
            if qr_b64:
                qr_base64 = qr_b64
            txn = {
                "order_id": payload.get("order_id"),
                "transaction_id": payload.get("transaction_id"),
                "client_transaction_id": payload.get("client_transaction_id"),
                "amount": payload.get("amount"),
                "currency": payload.get("currency"),
            }
        except Exception:
            txn = {}
    # Last-resort only: build a UPI URI only when the API returned neither
    # a QR image nor an intent URL. Otherwise the API's own data is used.
    if not upi_uri and not qr_base64:
        upi_uri = _upi_intent_uri(order_num, upi_amount or amt, tr=jtid or None)
    # Derive the payee VPA from the API's own intent URL when present
    merchant_vpa = ""
    if upi_uri and "pa=" in upi_uri:
        try:
            from urllib.parse import urlparse, parse_qs
            parsed_pa = parse_qs(urlparse(upi_uri.replace("upic:", "")).query).get("pa", [""])[0]
            merchant_vpa = parsed_pa or ""
        except Exception:
            merchant_vpa = ""
    # Extract share_payment_details if present
    share_details = d.get("share_payment_details") or {}

    was_first = bool(acc.get("is_first_order"))
    if acc.get("is_first_order"):
        acc["is_first_order"] = False
        acc["order_placed"] = True
    order = {
        "order_num": order_num,
        "sub_order_num": f"{order_num}_1",
        "status_id": "STATUS_ID_AWAITING_PAYMENT",
        "status_text": "Awaiting Payment",
        "status_color": "#E67E22",
        "quantity": st["total_quantity"] or 1,
        "size": (st["items"] or [{}])[0].get("variation", ""),
        "name": (st["items"] or [{}])[0].get("name"),
        "image": (st["items"] or [{}])[0].get("image"),
        "amount": amt,
        "upi_amount": int(round(upi_amount)) if upi_amount else amt,
        "payment_mode": "upi",
        "is_first_order": was_first,
        "auto_cancel": bool(db.get("auto_cancel_orders", True)),
        "device_id": _device_id(),
        "upi_uri": upi_uri,
        "qr_image": qr_base64 or "",
        "share_message": share_details.get("share_message", ""),
        "cart_session": cs,
        "juspay_order_id": jtid or "",
        "txn": txn,
        "created_at": int(time.time()),
    }
    db["orders"].insert(0, order)
    _persist()
    # UPI QR order is NOT paid yet. Keep the cart and the QR so the user can
    # scan/pay; payment_state flips to ORDERED only when the live payment check
    # (GET /api/v3/payments/{juspay_order_id}/status?sync=true) returns SUCCESS.
    # Never clear the cart or mark "Order Placed" on an unpaid UPI order.
    initial_state = "pending"
    if jtid:
        v3 = await _v3_payment_status(jtid)
        if v3 and v3.get("live"):
            initial_state = _v3_state(v3.get("status"))
    if initial_state == "confirmed":
        order["status_id"] = "STATUS_ID_ORDERED"
        order["status_text"] = "Order Placed"
        order["status_color"] = "#038D63"
        _persist()
        await _clear_cart_after_order(cs, st["items"] or [])
    resp_out = {
        "ok": True,
        "live": True,
        "order_num": order_num,
        "amount": amt,
        "upi_amount": int(round(upi_amount)) if upi_amount else amt,
        "upi_uri": upi_uri,
        "qr_image": qr_base64,
        "package_name": package_name,
        "redirect_url": "upi://pay",
        "merchant": {"name": "Meesho", "vpa": merchant_vpa or "", "cate": 5262,
                 "source": "qr" if qr_base64 else ("api" if merchant_vpa else "fallback")},
        "txn": txn,
        "juspay_order_id": jtid or "",
        "cart_session": cs,
        "address": addr,
        "share_message": share_details.get("share_message", ""),
        "payment_state": initial_state,
        "message": ("Payment received — order placed!" if initial_state == "confirmed"
                    else "UPI order created — scan the QR to pay. Awaiting payment."),
    }
    _charge_order(_usr)
    return resp_out


@app.post("/api/order/payment_status")
async def api_order_payment_status(data: dict = None):
    data = data or {}
    onum = str((data or {}).get("order_num") or "")
    cs = data.get("cart_session")
    o = next((x for x in db["orders"] if str(x.get("order_num")) == onum), None)
    state = await _universal_payment_check(o or {"order_num": onum}) if onum else None
    if state and state.get("live") and state.get("state") != "unknown":
        # If payment confirmed, update local order + clear cart
        if state["state"] == "confirmed":
            for oo in db["orders"]:
                if str(oo.get("order_num")) == onum:
                    oo["status_id"] = "STATUS_ID_ORDERED"
                    oo["status_text"] = "Order Placed"
                    oo["status_color"] = "#038D63"
            _persist()
            await _clear_cart_after_order(cs or db["cart"].get("cart_session") or "", [])
        elif state["state"] == "failed":
            for oo in db["orders"]:
                if str(oo.get("order_num")) == onum:
                    oo["status_id"] = "STATUS_ID_CANCELLED"
                    oo["status_text"] = "Payment Failed"
                    oo["status_color"] = "#E74C3C"
            _persist()
        return {"order_num": onum, "state": state["state"], "status": state.get("status"),
                "source": state.get("source"), "live": True}
    if not o:
        return {"order_num": onum, "state": "unknown", "status": "UNKNOWN"}
    state = "confirmed" if str(o.get("status_id", "")).upper() != "AWAITING_PAYMENT" else "pending"
    return {"order_num": onum, "state": state, "status": o.get("status_text", "PENDING")}


@app.post("/api/order/confirm")
async def api_order_confirm(data: dict = None):
    """Only mark an online order CONFIRMED after the REAL Meesho status says paid.
    Never fabricate a 'Payment received' confirmation."""
    data = data or {}
    onum = str(data.get("order_num") or "")
    cs = data.get("cart_session") or db["cart"].get("cart_session") or ""
    if onum:
        o = next((x for x in db["orders"] if str(x.get("order_num")) == onum), None)
        state = await _universal_payment_check(o or {"order_num": onum})
        if state and state.get("state") == "confirmed":
            for oo in db["orders"]:
                if str(oo.get("order_num")) == onum:
                    oo["status_id"] = "STATUS_ID_ORDERED"
                    oo["status_text"] = str(state.get("status") or "Order Placed")
                    oo["status_color"] = "#038D63"
            _persist()
            await _clear_cart_after_order(cs, [])
            return {"ok": True, "message": "Payment received — your order is confirmed!", "live": True}
        if state and state.get("state") == "failed":
            for oo in db["orders"]:
                if str(oo.get("order_num")) == onum:
                    oo["status_id"] = "STATUS_ID_CANCELLED"
                    oo["status_text"] = "Payment Failed"
                    oo["status_color"] = "#E74C3C"
            _persist()
            return {"ok": False, "live": True, "error": "payment_failed",
                    "message": "Payment failed on Meesho's side — the order/payment could not be completed."}
        if state and state.get("state") == "pending":
            return {"ok": False, "live": True, "error": "still_pending",
                    "message": f"Payment is still {state.get('status')} on Meesho's side."}
    return {"ok": False, "live": True, "error": "not_confirmed",
            "message": "Meesho has not confirmed this payment yet."}


_STATUS_META = {
    "STATUS_ID_ORDERED": ("Order Placed", "#038D63"),
    "STATUS_ID_AWAITING_PAYMENT": ("Awaiting Payment", "#E67E22"),
    "STATUS_ID_PACKED": ("Packed", "#FFA800"),
    "STATUS_ID_SHIPPED": ("Shipped", "#2E86DE"),
    "STATUS_ID_TRANSIT": ("In Transit", "#2E86DE"),
    "STATUS_ID_OUT_FOR_DELIVERY": ("Out for Delivery", "#2E86DE"),
    "STATUS_ID_DELIVERED": ("Delivered", "#038D63"),
    "STATUS_ID_RETURN_REQUESTED": ("Return Requested", "#E74C3C"),
    "STATUS_ID_RETURNED": ("Returned", "#E74C3C"),
    "STATUS_ID_CANCELLED": ("Cancelled", "#E74C3C"),
    "STATUS_ID_RTO": ("RTO", "#E74C3C"),
}


def _status_meta(sid):
    sid = str(sid or "")
    t, c = _STATUS_META.get(sid, ("Order Placed", "#038D63"))
    return {"status_id": sid or "STATUS_ID_ORDERED", "status_text": t, "status_color": c}


async def _live_order_list(cursor=None, limit=10):
    """REAL Meesho order history (api/3.0/user/orders)."""
    h = _active_headers()
    if not h:
        return None
    acc = _active_account()
    body = {"limit": limit, "cursor": cursor, "query": None,
            "filters": {"sub_order_status": [0], "sub_order_created": None},
            "user_id": acc["user_id"]}
    resp = await meesho_request("POST", "https://prod.meeshoapi.com/api/3.0/user/orders",
                                json=body, headers=h, timeout=25)
    if not resp or resp.status_code != 200:
        return None
    d = _as_json(resp)
    if not isinstance(d, dict) or not d.get("sub_order_list"):
        return None
    out = []
    for i in d.get("sub_order_list") or []:
        pd_ = i.get("product_details") or {}
        st_ = (i.get("status") or {}) or {}
        title = (st_.get("title") or {}).get("text")
        tcolor = (st_.get("title") or {}).get("text_color")
        sub_ = (st_.get("sub_title") or {}) or {}
        pm_ = i.get("payment_details") or {}
        meta = _status_meta(i.get("sub_order_status"))
        if title:
            meta = {"status_id": i.get("sub_order_status") or meta["status_id"],
                    "status_text": title, "status_color": tcolor or meta["status_color"]}
        created = i.get("created_date")
        updated = None
        if isinstance(created, (int, float)) and created > 0:
            try:
                updated = datetime.datetime.fromtimestamp(created / 1000).strftime("%Y-%m-%dT%H:%M:%S")
            except Exception:
                updated = None
        out.append({
            "order_id": i.get("order_id"),
            "sub_order_id": i.get("sub_order_id"),
            "order_num": str(i.get("order_num") or ""),
            "sub_order_num": str(i.get("sub_order_num") or ""),
            "name": pd_.get("name"),
            "image": pd_.get("image"),
            "size": pd_.get("size"),
            "quantity": pd_.get("quantity"),
            "catalog_id": pd_.get("catalog_id"),
            "updated_date": updated,
            "delivery_date": sub_.get("date"),
            "payment_mode": pm_.get("final_payment_mode"),
            "live": True,
            **meta,
        })
    return {"orders": out, "cursor": None, "live": True}


async def _live_order_detail(order_num, sub_order_num=None):
    """REAL Meesho per-order detail (api/3.0/user/order-details)."""
    h = _active_headers()
    if not h:
        return None
    acc = _active_account()
    sub = sub_order_num or f"{order_num}_1"
    body = {"order_num": str(order_num), "sub_order_num": str(sub), "user_id": acc["user_id"]}
    resp = await meesho_request("POST", "https://prod.meeshoapi.com/api/3.0/user/order-details",
                                json=body, headers=h, timeout=25)
    if not resp or resp.status_code != 200:
        return None
    d = _as_json(resp)
    if not isinstance(d, dict) or not d.get("order_num"):
        return None

    pd_ = d.get("product_details") or {}
    trk = d.get("tracking_details") or {}
    st_ = (trk.get("status") or {}) or {}
    sub_title = (st_.get("sub_title") or {}) or {}
    adr = (d.get("address_details") or {}) or {}
    adr = adr.get("address") or adr
    pay = d.get("payment_details") or {}
    tls = d.get("timeline_bottom_sheet") or {}
    sup = d.get("supplier_details") or {}

    meta = _status_meta(d.get("order_status"))
    ttitle = (st_.get("title") or {}).get("text")
    if ttitle:
        meta = {"status_id": d.get("order_status") or meta["status_id"],
                "status_text": ttitle, "status_color": (st_.get("title") or {}).get("text_color") or meta["status_color"]}

    milestones = []
    tl = (trk.get("timeline") or {}) or {}
    for i, m in enumerate((tl.get("milestones") or [])):
        sm = m.get("sub_milestone") or {}
        card = sm.get("card") or {}
        is_cur = bool(m.get("active"))
        milestones.append({
            "status": m.get("status") or "",
            "date": m.get("date") or "",
            "done": is_cur,
            "is_current": is_cur,
            "current_text": card.get("status"),
        })

    log = []
    for m in (tls.get("milestones") or []):
        log.append({
            "status": m.get("status") or "",
            "date": m.get("date") or "",
            "time": m.get("time") or "",
            "active": bool(m.get("active")),
            "text_color": m.get("text_color"),
        })

    images = pd_.get("images") or []
    if isinstance(images, str):
        images = [images]
    if not images and pd_.get("image"):
        images = [pd_.get("image")]

    mode = str(pay.get("final_payment_mode") or "")
    mode_label = "Cash on Delivery" if ("ash" in mode or "COD" in mode.upper()) else ("Paid Online" if mode else None)
    discount = (pay.get("total_discount") or {}) or {}
    total = pay.get("price_to_be_paid")
    if total is None:
        pay_rows = pay.get("payment_break_up_details") or []
        total = None
        for r_ in pay_rows:
            if isinstance(r_, dict) and isinstance(r_.get("amount"), (int, float)) and (r_.get("amount") or 0) > 0:
                total = (total or 0) + r_.get("amount")
    return {
        "order_num": str(d.get("order_num")),
        "sub_order_num": str(d.get("sub_order_num")),
        "status_id": meta["status_id"],
        "status_text": meta["status_text"],
        "status_color": meta["status_color"],
        "product": {
            "product_id": pd_.get("id"),
            "catalog_id": pd_.get("catalog_id"),
            "name": pd_.get("name") or "Order item",
            "size": pd_.get("size"),
            "quantity": pd_.get("quantity"),
            "images": [images[0]] if images else [],
        },
        "tracking": {
            "icon": st_.get("icon_url"),
            "title": meta["status_text"],
            "delivery_by": sub_title.get("date"),
        },
        "milestones": milestones,
        "log": log,
        "shipment": None,
        "awb": None,
        "address": {
            "name": adr.get("name"),
            "line1": adr.get("address_line_1"),
            "line2": adr.get("address_line_2"),
            "landmark": adr.get("landmark"),
            "city": adr.get("city"),
            "state": adr.get("state"),
            "pin": adr.get("pin"),
            "mobile": adr.get("mobile"),
        },
        "payment": {
            "mode": mode_label,
            "total": pay.get("price_to_be_paid"),
            "saved": discount.get("amount"),
            "price_type": (pay.get("price_type") or {}).get("tag"),
            "price_type_id": (pay.get("price_type") or {}).get("id"),
            "break_up": pay.get("payment_break_up_details"),
            "bill": (pay.get("bill_details") or {}).get("bill_break_up"),
        },
        "supplier": {"name": sup.get("name")},
        "carrier": tls.get("carrier"),
        "cancellable": False,
        "live": True,
    }


def _stored_order_detail(o):
    """Fallback detail from a REAL order we placed ourselves — never fabricates."""
    addr = db["cart"]["address"] or (_account_address_by_id() or {})
    meta = _status_meta(o.get("status_id"))
    images = [o["image"]] if o.get("image") else []
    return {
        "order_num": str(o.get("order_num") or ""),
        "sub_order_num": None,
        "status_id": o.get("status_id") or meta["status_id"],
        "status_text": o.get("status_text") or meta["status_text"],
        "status_color": o.get("status_color") or meta["status_color"],
        "product": {"product_id": None, "name": o.get("name") or "Order item",
                    "size": o.get("size"), "quantity": o.get("quantity"),
                    "images": images},
        "tracking": {"title": o.get("status_text") or meta["status_text"], "delivery_by": None},
        "milestones": [{"status": meta["status_text"], "date": "Today", "done": True, "is_current": True}],
        "log": [{"status": meta["status_text"], "date": "Today", "time": "", "active": True,
                 "text_color": meta["status_color"]}],
        "shipment": None, "awb": None,
        "address": {"name": addr.get("name"), "line1": addr.get("address_line_1"),
                    "line2": addr.get("address_line_2"), "landmark": addr.get("landmark"),
                    "city": addr.get("city"), "state": addr.get("state"), "pin": addr.get("pin"),
                    "mobile": addr.get("mobile")},
        "payment": {"mode": None, "total": o.get("amount"), "saved": None,
                    "price_type": o.get("price_type")},
        "supplier": None,
        "cancellable": False,
        "live": False,
    }


@app.post("/api/orders/detail")
async def api_order_detail(data: dict = None):
    data = data or {}
    onum = str(data.get("order_num") or "")
    if not onum:
        return {"error": "Order not found"}
    detail = await _live_order_detail(onum, data.get("sub_order_num"))
    if detail:
        return detail
    o = None
    for x in db["orders"]:
        if str(x.get("order_num")) == onum:
            o = x
            break
    if o:
        return _stored_order_detail(o)
    return {"error": "Order not found"}


@app.get("/api/orders")
async def api_get_orders(status: Optional[int] = 0, cursor: Optional[str] = None):
    live = await _live_order_list(cursor, 10)
    if live:
        items = live["orders"]
        if status:
            filtered = []
            for o in items:
                st = str(o.get("status_id", "")).upper()
                if status == 1 and ("CANCEL" in st or "RTO" in st): filtered.append(o)
                elif status == 2 and ("OUT_FOR_DELIVERY" in st or "SHIPPED" in st or "TRANSIT" in st or "DISPATCH" in st): filtered.append(o)
                elif status == 3 and "DELIVERED" in st: filtered.append(o)
                else: filtered.append(o)
            items = filtered
        return {"orders": items, "filters": [
            {"id": 0, "name": "All"},
            {"id": 1, "name": "Cancelled"},
            {"id": 2, "name": "In Transit"},
            {"id": 3, "name": "Delivered"},
        ], "cursor": None, "live": True,
            "message": "These are your real Meesho orders. They also appear inside the Meesho app."}
    items = []
    for o in db["orders"]:
        meta = _status_meta(o.get("status_id"))
        items.append({
            "order_id": int(o.get("order_num") or 0) if str(o.get("order_num") or "").isdigit() else None,
            "order_num": str(o.get("order_num") or ""),
            "sub_order_num": str(o.get("sub_order_num") or o.get("order_num") or ""),
            "name": o.get("name"),
            "image": o.get("image"),
            "size": o.get("size"),
            "quantity": o.get("quantity"),
            "amount": o.get("amount"),
            "payment_mode": "prepaid" if o.get("upi_amount") else "cod",
            "juspay_order_id": o.get("juspay_order_id") or "",
            "payment_state": "confirmed" if str(o.get("status_id", "")).upper() == "STATUS_ID_ORDERED" else "pending",
            "cart_session": o.get("cart_session") or "",
            "live": False,
            **meta,
        })
    if status:
        items = [o for o in items if (
            (status == 1 and "CANCEL" in str(o.get("status_id", "")).upper()) or
            (status == 2 and any(k in str(o.get("status_id", "")).upper() for k in ("OUT_FOR_DELIVERY", "SHIPPED", "TRANSIT", "DISPATCH"))) or
            (status == 3 and "DELIVERED" in str(o.get("status_id", "")).upper()) or
            (status == 0)
        )]
    return {"orders": items, "filters": [
        {"id": 0, "name": "All"},
        {"id": 1, "name": "Cancelled"},
        {"id": 2, "name": "In Transit"},
        {"id": 3, "name": "Delivered"},
    ], "cursor": None, "live": False, "message": "Your real Meesho orders are shown above."}


@app.get("/api/orders/cancel_reasons")
async def api_order_cancel_reasons(order_num: Optional[str] = None, sub_order_num: Optional[str] = None):
    live = await _real_cancel_reasons(order_num or "", sub_order_num or None)
    if live:
        reasons = live.get("cancellation_reasons") or []
        if reasons:
            return {"reasons": reasons, "live": True}
    return {"reasons": [
        {"id": 1, "description": "I changed my mind", "comment_required": False},
        {"id": 2, "description": "Order taking too long", "comment_required": False},
        {"id": 3, "description": "Found cheaper elsewhere", "comment_required": False},
        {"id": 4, "description": "Other reason", "comment_required": True},
    ], "live": False}


async def _real_cancel_reasons(order_num, sub_order_num=None):
    """REAL Meesho cancel reasons (captured live from the app):
    GET /api/2.0/orders/{order_num}/sub-orders/{sub}/cancellations/fetch-reasons
    ?address_change_view_key=ADDRESS_CHANGE -> {"cancellation_reasons": [...]}"""
    h = _active_headers()
    if not h or not order_num:
        return None
    sub = sub_order_num or f"{order_num}_1"
    url = (f"https://prod.meeshoapi.com/api/2.0/orders/{order_num}"
           f"/sub-orders/{sub}/cancellations/fetch-reasons"
           f"?address_change_view_key=ADDRESS_CHANGE")
    resp = await meesho_request("GET", url, headers=h, timeout=25)
    if resp and resp.status_code == 200:
        d = _as_json(resp)
        if isinstance(d, dict):
            return d
    return None


async def _real_cancel_order(order_num, sub_order_num=None, reason_id=None, comments=""):
    """REAL Meesho order cancellation. Captured from the app:
    POST /api/2.0/orders/{order_num}/sub-orders/{sub}/cancellations
    body: reason_id=20&comments=Abcd  (application/x-www-form-urlencoded)
    Success -> HTTP 200 with a bare list ([{}]).
    Returns True on success, a dict (error) on a 200-with-error, None otherwise."""
    h = _active_headers()
    if not h or not order_num:
        return None
    sub = sub_order_num or f"{order_num}_1"
    if not reason_id:
        d = await _real_cancel_reasons(order_num, sub)
        reasons = (d or {}).get("cancellation_reasons") or []
        for r in reasons:
            if not r.get("on_click_view"):
                reason_id = r.get("id")
                break
        if not reason_id and reasons:
            reason_id = reasons[0].get("id")
    from urllib.parse import quote
    rid = str(int(reason_id or 1))
    body = "reason_id=%s&comments=%s" % (rid, quote(str(comments or ""), safe=""))
    url = (f"https://prod.meeshoapi.com/api/2.0/orders/{order_num}"
           f"/sub-orders/{sub}/cancellations")
    resp = await meesho_request(
        "POST", url, headers={**h, "Content-Type": "application/x-www-form-urlencoded"},
        data=body, timeout=30)
    if resp is None:
        return None
    if resp.status_code == 200:
        d = _as_json(resp) if resp.text else []
        if isinstance(d, list):
            return True
        if isinstance(d, dict):
            if d.get("success") or "CANCELLED" in str(d.get("order_status") or "").upper():
                return True
            return d
        return True
    return None


@app.post("/api/orders/cancel")
async def api_order_cancel(data: dict = None):
    data = data or {}
    onum = str(data.get("order_num") or "")
    sub = str(data.get("sub_order_num") or "")
    rid = data.get("reason_id")
    comments = str(data.get("comments") or "")
    try:
        live = await _real_cancel_order(onum, sub, rid, comments)
    except Exception:
        live = None
    if live is True:
        for o in db["orders"]:
            if str(o.get("order_num")) == onum:
                o["status_id"] = "CANCELLED"
                o["status_text"] = "Order Cancelled"
                o["status_color"] = "#E53935"
                o.pop("cancel_error", None)
        _persist()
        return {"ok": True, "live": True, "message": "Order cancelled on Meesho."}
    if isinstance(live, dict):
        err = str(live.get("error") or live.get("message") or live.get("status") or live)[:140]
        return {"ok": False, "live": False,
                "message": f"Meesho rejected the cancellation: {err}"}
    return {"ok": False, "live": False,
            "message": "Meesho could not cancel this order right now (it is still payment-pending / not cancellable yet). It will be retried by the auto-cancel task or auto-expire unpaid."}


# ---------------- REFERRAL / WALLET / OFFER ----------------
@app.get("/api/referral/stats")
async def api_referral_stats():
    # Never present fabricated referral earnings. These values are only returned
    # when the backend has real referral state; otherwise they remain zero.
    return {"done": int(db.get("referral_done", 0) or 0),
            "pending": int(db.get("referral_pending", 0) or 0),
            "rejected": int(db.get("referral_rejected", 0) or 0),
            "earned": float(db.get("referral_earned", 0) or 0),
            "link": db.get("referral_link") or "",
            "has_link": bool(db.get("referral_link"))}

@app.post("/api/referral/prepare")
async def api_referral_prepare(data: dict = None):
    """Prepare a referral attribution using the real invite/deep-link flow.

    The supplied value is never treated as an already-applied referral.  When
    the value itself is a valid HTTPS invite link, the client is instructed to
    open that link so the Meesho app can receive the referral context.  A bare
    code is retained for the login flow, but is not falsely reported as applied.
    """
    from urllib.parse import urlparse
    data = data or {}
    value = str(data.get("referral") or data.get("code") or data.get("link") or "").strip()
    if not value:
        return {"ok": False, "applied": False, "message": "Enter a referral code or invite link."}
    if len(value) > 500:
        return {"ok": False, "applied": False, "message": "Referral value is too long."}

    db["pending_referral"] = value
    _persist()

    parsed = urlparse(value)
    is_https_link = parsed.scheme == "https" and bool(parsed.netloc)
    if is_https_link:
        return {"ok": True, "applied": False, "pending": True,
                "open_link": value,
                "message": "Invite link ready. Open it to pass referral attribution to Meesho."}

    return {"ok": True, "applied": False, "pending": True,
            "message": "Referral code saved. Continue login/account onboarding so the invite attribution can be completed."}


@app.get("/api/account/fod")
async def api_fod():
    acc = next((a for a in db["accounts"] if a.get("id") == db["active_id"]), None)
    if not acc:
        return {"offer": None, "rolled": False, "message": "Select an account first."}
    eligible = bool(acc.get("is_first_order")) and not acc.get("order_placed")
    if not eligible:
        return {"offer": None, "message": "This account is not a first-time buyer — no 1st-order offer applies.",
                "bucket": "NONE", "rolled": False, "bound": False}
    offer = db.get("picked_offer")
    if acc.get("order_placed"):
        return {"offer": None, "message": "Discount already used on this account.", "bucket": acc.get("bucket", "USED")}
    bound = acc.get("bound_offer")
    if bound:
        return {"offer": bound, "bucket": bound.get("id"), "bound": True}
    if offer:
        return {"offer": offer, "bucket": offer.get("id"), "bound": False, "rolled": True}
    return {"offer": None, "bucket": "FREE", "rolled": False, "bound": False}


@app.get("/api/fod/roll")
async def api_fod_roll():
    """Return only the active account's server-confirmed first-order offer.
    Never fabricate a promo or rotate anonymous identities to obtain a different bucket."""
    try:
        acc = _active_account()
        if not acc:
            return {"ok": False, "live": False, "rolled": False,
                    "error": "Sign in and select an account first."}
        res = await _account_real_fod(acc)
        if res.get("ok") and res.get("offer"):
            offer = dict(res["offer"])
            offer["live"] = True
            return {"ok": True, "offer": offer, "rolled": True, "live": True,
                    "is_first_order": bool(res.get("is_first_order"))}
        return {"ok": bool(res.get("ok")), "live": bool(res.get("live")),
                "rolled": False, "offer": None,
                "error": res.get("message") or "No live offer available."}
    except Exception as e:
        return {"ok": False, "live": False, "rolled": False,
                "error": f"Live offer check failed: {type(e).__name__}: {e}"}


@app.get("/api/account/fod")
async def api_account_fod():
    """Report the ACTIVE account's REAL first-order-discount state, read live from
    Meesho's cart review (user_meta.is_first_order). For a JSON-imported account
    this tells us exactly what FOD it already has acquired server-side — rather
    than a fabricated/rolled offer."""
    try:
        res = await _account_real_fod()
        if not res.get("ok"):
            return {"ok": False, "live": False, "message": res.get("message")}
        return {"ok": True, "live": True,
                "is_first_order": res.get("is_first_order"),
                "offer": res.get("offer"),
                "message": res.get("message")}
    except Exception as e:
        return {"ok": False, "live": False, "message": f"{type(e).__name__}: {e}"}


@app.post("/api/fod/continue")
async def api_fod_continue(data: dict = None):
    """Lock only the offer returned by the active account's live server state.
    Client-submitted promo values are never trusted."""
    acc = _active_account()
    if not acc:
        return {"ok": False, "live": False, "error": "Select an account first."}
    res = await _account_real_fod(acc)
    if not res.get("ok"):
        return {"ok": False, "live": False, "error": res.get("message") or "Live offer check failed."}
    offer = res.get("offer")
    if not offer:
        return {"ok": False, "live": True, "error": "No live first-order offer is available for this account."}
    db["picked_offer"] = dict(offer)
    db["picked_offer"]["live"] = True
    _persist()
    return {"ok": True, "live": True, "offer": db["picked_offer"]}


# bind an offer to a NEW number via OTP (continues the picked offer)
@app.post("/api/fod/bind/login_otp")
async def api_fod_bind_otp(data: dict = None):
    data = data or {}
    phone = re.sub(r"\D", "", str(data.get("phone_number", "")))[-10:]
    if not phone.isdigit() or len(phone) < 10:
        return {"ok": False, "error": "Enter a valid 10-digit number"}
    offer = db.get("picked_offer") or {}
    res = await meesho_request_otp(phone)
    if not res["ok"]:
        return {"ok": False, "phone": phone, "live": False,
                "error": res.get("error", "Could not send OTP")}
    db["pending_binds"][phone] = {"offer": offer, "request_id": res["request_id"], "instance_id": res["instance_id"]}
    return {"ok": True, "phone": phone, "offer": offer, "request_id": res["request_id"], "instance_id": res["instance_id"], "live": True}


@app.post("/api/fod/bind/login_verify")
async def api_fod_bind_verify(data: dict = None):
    data = data or {}
    phone = re.sub(r"\D", "", str(data.get("phone_number", "")))[-10:]
    otp = str(data.get("otp", ""))
    pend = db["pending_binds"].pop(phone, None)
    if not pend:
        return {"ok": False, "error": "No pending bind for this number — send a fresh OTP first.", "live": True}
    res = await meesho_verify_otp(phone, otp, pend.get("request_id", ""), pend.get("instance_id", ""))
    if not res["ok"]:
        return {"ok": False, "error": res.get("error", "Verification failed")}
    record_phone_truth(phone, res)
    offer = pend.get("offer") or {}
    for a in db["accounts"]:
        a["order_placed"] = False
    acc = {
        "id": len(db["accounts"]) + 1,
        "mobile": phone,
        "user_id": res.get("user_id"),
        "cookies": res.get("cookies"),
        "xo": res.get("xo"),
        "xo_exp": res.get("xo_exp") or 1795000000,
        "instance_id": res.get("instance_id"),
        "source": "fod_otp",
        "order_placed": False,
        "is_first_order": True,
        "bound_offer": offer,
        "bucket": offer.get("id"),
        "bucket_text": offer.get("text", offer.get("text") or "100% Free"),
    }
    db["accounts"].append(acc)
    db["active_id"] = acc["id"]
    return {"ok": True, "account": acc, "offer": offer, "live": res.get("live", False)}


@app.post("/api/check_number")
async def api_check_number(data: dict = None):
    data = data or {}
    phone = re.sub(r"\D", "", str(data.get("phone_number", "")))[-10:]
    if not phone.isdigit() or len(phone) != 10:
        return {"ok": False, "error": "Enter a valid 10-digit number"}
    return {"ok": False, "live": False, "phone": phone, "eligible": False,
            "error": "Authenticate this number first. Send OTP below; after verification the server checks the account's real offer."}


SUPERASSETS_CHECK_URL = "https://superassets.in/api/v1/check"
SUPERASSETS_API_KEY = "AK_F0pGXwFH1xKuqoYUkjb2tkwu38PnzF_d"


async def superassets_check_mobile(phone: str) -> dict:
    """Query the external superassets.in registrar for a real, authoritative
    Meesho fresh-or-registered verdict on a mobile number (NO OTP needed)."""
    phone = re.sub(r"\D", "", str(phone))[-10:]
    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(
                SUPERASSETS_CHECK_URL,
                headers={
                    "X-API-Key": SUPERASSETS_API_KEY,
                    "Content-Type": "application/json",
                },
                json={"service": "meesho", "number": phone},
            )
            data = {}
            if resp.status_code == 200:
                data = resp.json() or {}
            return data
    except Exception:
        return {}


@app.post("/api/check_registered")
async def api_check_registered(data: dict = None):
    """Instant NO-OTP registration check.

    Real up-front check is answered by the superassets.in registrar service
    (see superassets_check_mobile): it queries the actual user database and
    returns is_registered:true (used before) or false (FRESH/never used) without
    sending any OTP.

    The local phone_status cache is used only as a fast path, and only when the
    external service does not respond (is_down / no is_registered). This endpoint
    NEVER sends an OTP.
    """
    data = data or {}
    phone = re.sub(r"\D", "", str(data.get("phone_number", "")))
    phone = phone[-10:]
    if not phone.isdigit() or len(phone) != 10:
        return {"ok": False, "error": "Enter a valid 10-digit number"}

    ext = await superassets_check_mobile(phone)
    if ext.get("success") and ext.get("is_registered") is not None and not ext.get("is_down"):
        registered = bool(ext.get("is_registered"))
        is_new = not registered
        record_phone_truth(phone, {
            "live": True, "is_new": is_new,
            "registered": registered,
            "sign_up_date": None,
        })
        return {"ok": True, "phone": phone, "verified": True,
                "checked_by": "superassets",
                "registered": registered,
                "is_new": is_new,
                "sign_up_date": None}

    # External service unreachable/down -> fall back to locally verified truth
    known = (db.get("phone_status") or {}).get(phone)
    if known:
        return {"ok": True, "phone": phone, "verified": True,
                "registered": known.get("registered"),
                "is_new": known.get("is_new"),
                "sign_up_date": known.get("sign_up_date"),
                "checked_at": known.get("checked_at")}

    return {"ok": True, "phone": phone, "verified": False,
            "registered": None, "is_new": None,
            "note": "Checker service unreachable and no local record for this number."}


@app.get("/api/check_number")
async def api_check_number_get():
    return {"ok": True, "eligible": True, "title": "🎉 Enter a number to check 1st-order eligibility"}


@app.get("/api/wallet/history")
async def api_wallet_history():
    return {"balance": 0, "txns": []}




# ================= Render worker mode (merged from worker.py) =================
#!/usr/bin/env python3
"""Single worker for Telegram bot + optional auto-cancel task."""
import json
import os
import time
import traceback

import httpx

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(BASE_DIR, "bot_config.json")


def load_cfg():
    cfg = {}
    try:
        with open(CFG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f) or {}
    except Exception:
        pass
    cfg["token"] = os.environ.get("BOT_TOKEN", cfg.get("token", "")).strip()
    cfg["shop_url"] = os.environ.get("SHOP_URL", cfg.get("shop_url", "")).rstrip("/")
    cfg.setdefault("welcome_text", "🛍️ Open the shop:")
    return cfg

CFG = load_cfg()
TOKEN = CFG["token"]
SHOP_URL = CFG["shop_url"]
API = "https://api.telegram.org/bot" + TOKEN


def api_call(method, **params):
    r = httpx.post(API + "/" + method, json=params, timeout=60)
    r.raise_for_status()
    return r.json()


def current_shop_url():
    """Re-read the live shop/tunnel URL every time so inline buttons + the webapp
    always point to the CURRENT cloudflared URL, even after it auto-rotates."""
    try:
        with open(os.path.join(BASE_DIR, "current_tunnel_url"), "r", encoding="utf-8") as f:
            u = f.read().strip()
            if u.startswith("https://"):
                return u
    except Exception:
        pass
    try:
        with open(CFG_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("shop_url", SHOP_URL).rstrip("/")
    except Exception:
        return SHOP_URL


def send_start(chat_id, text=None, reply_to=None):
    text = text or CFG.get("welcome_text") or "Open the shop:"
    url = current_shop_url()
    keyboard = {
        "inline_keyboard": [
            [{"text": "🛍️ Open Shop", "web_app": {"url": url}}],
        ]
    }
    api_call("sendMessage", chat_id=chat_id, text=text,
             parse_mode="HTML", reply_markup=keyboard)


def handle_message(m):
    chat_id = m.get("chat", {}).get("id")
    text = (m.get("text") or "").strip().lower()
    if not chat_id:
        return
    if text in ("/start", "/open", "/menu", "/shop", "open shop", "shop", "open"):
        send_start(chat_id)
    else:
        send_start(chat_id)


def main():
    print("token_valid=getMe", flush=True)
    me = api_call("getMe")
    print("bot =@" + (me["result"].get("username") or "?"), flush=True)
    try:
        api_call("deleteWebhook", drop_pending_updates=True)
    except Exception:
        pass

    def refresh_menu():
        try:
            api_call("setChatMenuButton", menu_button={
                "type": "web_app", "text": "🛍️ Open Shop",
                "web_app": {"url": current_shop_url()}
            })
            return True
        except Exception:
            return False

    try:
        refresh_menu()
        print("menu_button=ok", flush=True)
    except Exception as e:
        print("menu_button=skip (" + str(e) + ")", flush=True)

    last_id = 0
    last_menu_refresh = time.time()
    while True:
        try:
            # Re-point the sidebar webapp button whenever the tunnel URL changed
            if time.time() - last_menu_refresh >= 30:
                if refresh_menu():
                    last_menu_refresh = time.time()
            up = api_call("getUpdates", timeout=30, limit=50,
                          offset=last_id + 1 if last_id else -1,
                          allowed_updates=["message", "callback_query"])
            for u in up.get("result", []):
                last_id = max(last_id, u.get("update_id", last_id))
                try:
                    if "message" in u:
                        handle_message(u["message"])
                except Exception:
                    traceback.print_exc()
        except Exception:
            traceback.print_exc()
            print("poll_backoff 5s", flush=True)
            time.sleep(5)


import json, os, sys, time, urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(BASE, "state")
DB_FILE = os.path.join(STATE_DIR, "db.json")
LOG_FILE = os.path.join(STATE_DIR, "autocancel.log")
STATUS_FILE = os.path.join(STATE_DIR, "autocancel.status.json")
SERVER = os.environ.get("SERVER_URL", "http://127.0.0.1:5000").rstrip("/")
WINDOW = int(float(os.environ.get("AUTOCANCEL_HOURS", "5")) * 3600)
INTERVAL = int(os.environ.get("AUTOCANCEL_INTERVAL", "90"))
BLOCKED = ("CANCEL", "RTO", "RETURN", "DELIVERED")


def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def load_status():
    try:
        with open(STATUS_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def save_status(d):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = STATUS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, STATUS_FILE)
    except Exception:
        pass


def saas_login():
    """Log into the SaaS layer (admin) so cancellations use the tenant session."""
    import urllib.request
    body = json.dumps({"username": os.environ.get("ADMIN_USER", "admin"),
                       "password": os.environ.get("ADMIN_PASS", "admin123")}).encode()
    req = urllib.request.Request(SERVER + "/api/auth/login", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read() or "{}")
        if d.get("ok") and d.get("token"):
            return str(d["token"])
    except Exception as e:
        log(f"saas login failed: {e}")
    return None


def cancellable(o):
    blob = (str(o.get("status_text") or "") + " " + str(o.get("status_id") or "")).upper()
    return not any(b in blob for b in BLOCKED)


def auto_cancel_main():
    st = load_status() or {}
    now = time.time()
    start = float(st.get("start", now))
    deadline = float(st.get("deadline", start + WINDOW))
    if deadline <= now and st:
        # expired run — a new (re)start begins a fresh window
        start = now
        deadline = now + WINDOW
    elif deadline <= now:
        deadline = now + WINDOW
    log(f"auto-cancel worker started. window={WINDOW}s, start={int(start)}, deadline={int(deadline)} "
        f"(ends {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(deadline))})")

    token = saas_login()
    if token:
        log("saas login OK — cancellations will be tenant-scoped (X-Session).")

    done = set(st.get("done") or [])
    summary = {"cycles": st.get("cycles", 0), "cancelled": st.get("cancelled", 0),
               "failed": st.get("failed", 0), "pending_retry": st.get("pending_retry", 0)}

    while True:
        now = time.time()
        save_status({"start": start, "deadline": deadline, "done": sorted(done), **summary})
        if now >= deadline:
            log(f"DEADLINE reached. {summary['cycles']} cycles, "
                f"{summary['cancelled']} cancelled live, {summary['pending_retry']} still pending, "
                f"{summary['failed']} failures. Exiting.")
            save_status({"start": start, "deadline": deadline, "done": sorted(done), **summary,
                         "finished": True})
            return 0

        summary["cycles"] += 1
        cycle = f"cycle {summary['cycles']} ({(deadline - now) / 60:.0f} min left)"
        found = 0

        try:
            with open(DB_FILE) as f:
                db = json.load(f)
        except Exception as e:
            log(f"{cycle}: cannot read db.json: {e}")
            time.sleep(INTERVAL)
            continue

        for ns, stt in (db.get("devices") or {}).items():
            if not isinstance(stt, dict):
                continue
            for o in (stt.get("orders") or []):
                if not isinstance(o, dict):
                    continue
                onum = str(o.get("order_num") or "")
                if not onum or onum in done or not o.get("auto_cancel"):
                    continue
                if not cancellable(o):
                    continue
                found += 1
                sub = str(o.get("sub_order_num") or f"{onum}_1")
                did = str(o.get("device_id") or "").strip() or (ns.rsplit(":", 1)[-1] or "default")
                body = json.dumps({"order_num": onum, "sub_order_num": sub}).encode()
                hdr = {"Content-Type": "application/json", "X-Device-ID": did}
                if token:
                    hdr["X-Session"] = token
                req = urllib.request.Request(
                    SERVER + "/api/orders/cancel", data=body, headers=hdr, method="POST")
                try:
                    with urllib.request.urlopen(req, timeout=40) as r:
                        resp = json.loads(r.read() or "{}")
                except Exception as e:
                    summary["failed"] += 1
                    log(f"{cycle}: order {onum}: server unreachable/error: {e}")
                    continue
                if resp.get("ok") and resp.get("live"):
                    done.add(onum)
                    summary["cancelled"] += 1
                    log(f"{cycle}: CANCELLED LIVE order {onum} (device {did})")
                elif resp.get("ok"):
                    # local-only cancellation (already cancelled before) — count as done
                    done.add(onum)
                    log(f"{cycle}: order {onum}: cancelled locally by server (live:{resp.get('live')})")
                else:
                    summary["pending_retry"] += 1
                    log(f"{cycle}: order {onum}: NOT cancellable yet — {resp.get('message','')[:100]}")
        if found:
            save_status({"start": start, "deadline": deadline, "done": sorted(done), **summary})
        time.sleep(INTERVAL)




if __name__ == "__main__":
    import threading
    if os.environ.get("WORKER_MODE", "0").lower() in ("1", "true", "yes", "on"):
        if not TOKEN:
            raise SystemExit("BOT_TOKEN is not set. Set BOT_TOKEN environment variable.")
        main()
    else:
        import uvicorn
        port = int(os.environ.get("PORT", "10000"))
        uvicorn.run("app:app", host=os.environ.get("HOST", "0.0.0.0"), port=port, reload=False)
