"""Shared scanning logic for the Flask website and Tkinter desktop app."""
import csv
import ipaddress
import os
import re
import socket
from datetime import datetime
from urllib.parse import urlparse

HISTORY_FILE = "scan_history.csv"

SUSPICIOUS_WORDS = [
    "login", "verify", "password", "account", "secure", "update", "signin"
]
SHORTENED_DOMAINS = [
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly",
    "shorturl.at", "ow.ly", "buff.ly"
]


def validate_email(value: str) -> bool:
    """Check general email syntax only; this does not verify mailbox existence."""
    pattern = r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
    if not re.match(pattern, value):
        return False
    if ".." in value or value.startswith(".") or value.endswith("."):
        return False
    return True


def get_ip_address(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return "تعذر تحديد IP"


def calculate_risk(host: str, url: str, reasons: list[str]) -> tuple[str, int]:
    """A simple heuristic score, not a malware verdict."""
    score = 0
    if url.lower().startswith("http://"):
        score += 1
    if "@" in url:
        score += 2
    if host.startswith("xn--") or ".xn--" in host:
        score += 2

    lowered_host = host.lower()
    lowered_url = url.lower()
    score += sum(1 for word in SUSPICIOUS_WORDS
                 if word in lowered_host or word in lowered_url)

    # Add one point for each distinct warning reason not already counted above.
    extra_reasons = [
        reason for reason in reasons
        if not any(token in reason for token in ("HTTPS", "علامة @", "ترميز"))
    ]
    score += min(len(extra_reasons), 2)

    if score >= 4:
        return "مرتفع", score
    if score >= 2:
        return "متوسط", score
    return "منخفض", score


def scan_input(value: str) -> dict:
    value = (value or "").strip()
    if not value:
        return {
            "kind": "invalid", "status": "مدخل فارغ",
            "risk": None, "score": 0,
            "details": "الرجاء إدخال رابط أو بريد إلكتروني.",
            "reasons": [], "ip": None
        }

    if validate_email(value):
        return {
            "kind": "email", "status": "صيغة بريد مقبولة",
            "risk": "غير مطبق", "score": 0,
            "details": "صيغة البريد الإلكتروني تبدو صحيحة. هذا لا يؤكد وجود البريد أو أمانه.",
            "reasons": [], "ip": None
        }

    candidate = value if "://" in value else "https://" + value
    parsed = urlparse(candidate)

    try:
        host = parsed.hostname
        # Accessing .port can raise ValueError for malformed ports.
        _ = parsed.port
    except ValueError:
        host = None

    if (
        parsed.scheme not in ("http", "https")
        or not host
        or any(char.isspace() for char in value)
    ):
        return {
            "kind": "invalid", "status": "صيغة غير معروفة",
            "risk": None, "score": 0,
            "details": "تعذر التعرف على المدخل كرابط أو بريد إلكتروني صحيح الصيغة.",
            "reasons": [], "ip": None
        }

    host = host.lower()
    reasons = []

    if any(host == domain or host.endswith("." + domain)
           for domain in SHORTENED_DOMAINS):
        reasons.append("الرابط يستخدم خدمة اختصار؛ تحقق من الوجهة النهائية")

    if parsed.scheme == "http":
        reasons.append("الرابط لا يستخدم HTTPS")

    if "@" in parsed.netloc:
        reasons.append("وجود علامة @ في عنوان الرابط")

    if host.startswith("xn--") or ".xn--" in host:
        reasons.append("اسم النطاق يستخدم ترميزًا يستحق التحقق")

    if re.search(r"\d{5,}", host):
        reasons.append("وجود سلسلة أرقام طويلة في اسم النطاق")

    try:
        ipaddress.ip_address(host)
        reasons.append("الرابط يستخدم عنوان IP مباشرة")
    except ValueError:
        pass

    risk, score = calculate_risk(host, value, reasons)
    ip_address = get_ip_address(host)

    if reasons:
        details = "توجد مؤشرات تستحق الحذر. هذه المؤشرات لا تثبت أن الموقع ضار."
    else:
        details = "لم تُكتشف مؤشرات مريبة ضمن الفحوص الأولية. هذا لا يثبت أن الرابط آمن."

    return {
        "kind": "url",
        "status": "الخطورة: " + risk,
        "risk": risk,
        "score": score,
        "details": details,
        "reasons": reasons,
        "ip": ip_address,
        "host": host,
        "normalized_url": candidate
    }


def save_history(value: str, result: dict, history_file: str = HISTORY_FILE) -> None:
    file_exists = os.path.exists(history_file)
    with open(history_file, "a", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["التاريخ والوقت", "المدخل", "النوع", "النتيجة", "مستوى الخطورة", "النقاط", "التفاصيل"])
        details = result.get("details", "")
        if result.get("reasons"):
            details += " | " + "؛ ".join(result["reasons"])
        writer.writerow([
            datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
            value,
            result.get("kind", ""),
            result.get("status", ""),
            result.get("risk") or "",
            result.get("score", 0),
            details
        ])
