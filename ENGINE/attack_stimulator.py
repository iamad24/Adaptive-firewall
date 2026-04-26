import requests
import time
import random

BASE_URL = "http://127.0.0.1:5000"

# =========================
# IP POOLS
# =========================

# Realistic-looking IP ranges for each traffic type
NORMAL_IPS = [f"192.168.1.{i}" for i in range(1, 51)]        # LAN users
ATTACKER_IPS = [f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                for _ in range(30)]                            # Random public IPs
BOT_IPS = [f"103.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
           for _ in range(20)]                                 # Bot/scanner IPs
ANOMALY_IPS = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
               for _ in range(25)]                             # Internal-looking anomalies


def random_ip(pool):
    """Pick a random IP from a pool."""
    return random.choice(pool)


def spoof_headers(ip, extra=None):
    """
    Build headers that simulate a request coming from `ip`.
    X-Forwarded-For and X-Real-IP are the two headers most
    Flask/proxy setups read to determine the client IP.
    """
    headers = {
        "X-Forwarded-For": ip,
        "X-Real-IP":       ip,
    }
    if extra:
        headers.update(extra)
    return headers


# =========================
# HELPERS
# =========================

def send(path, headers=None):
    try:
        requests.get(f"{BASE_URL}{path}", headers=headers, timeout=3)
    except Exception:
        print("⚠️  Blocked / Error")

def banner(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}\n")


# =========================
# PHASE 1 — NORMAL USERS
# =========================

def phase1_normal_traffic():
    banner("PHASE 1 — NORMAL USERS 👨‍💻  (Training ML...)")
    normal_queries = [
        "home", "dashboard", "profile",
        "search user", "settings", "logout",
        "hello", "user123", "search data",
    ]
    for _ in range(40):
        q  = random.choice(normal_queries)
        ip = random_ip(NORMAL_IPS)
        send(f"/api/search?q={q}", headers=spoof_headers(ip))
        print(f"  ✅ NORMAL  [{ip}]  {q}")
        time.sleep(0.15)


# =========================
# PHASE 2 — SMALL ATTACKS
# =========================

def phase2_light_attacks():
    banner("PHASE 2 — SMALL ATTACKS ⚠️  (Light threats...)")

    xss_payloads = [
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "%3Cimg%20src=x%20onerror=alert(1)%3E",
        "%3Csvg%20onload=alert(1)%3E",
    ]
    sql_payloads = [
        "%27%20OR%201%3D1%20--",
        "%27%20UNION%20SELECT%201,2--",
        "%27%20DROP%20TABLE%20users--",
    ]
    path_payloads = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]

    attacks = (
        [("XSS",           p) for p in xss_payloads]  +
        [("SQL Injection",  p) for p in sql_payloads]  +
        [("Path Traversal", p) for p in path_payloads]
    )
    random.shuffle(attacks)

    for label, payload in attacks:
        ip = random_ip(ATTACKER_IPS)
        send(f"/api/search?q={payload}", headers=spoof_headers(ip))
        print(f"  🟡 {label}  [{ip}]  {payload[:40]}")
        time.sleep(0.8)


# =========================
# PHASE 3 — HEAVY ATTACKS
# =========================

def phase3_heavy_attacks():
    banner("PHASE 3 — HEAVY ATTACKS 🚨  (Creating spikes...)")

    bot_agents = ["sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster"]
    cmd_payloads = [
        "test; ls -la",
        "test && whoami",
        "`cat /etc/passwd`",
        "$(whoami)",
        "test | id",
    ]

    for i in range(30):
        choice = i % 3

        if choice == 0:
            # Rate-limit burst — same IP hammering rapidly (realistic DoS)
            ip = random_ip(ATTACKER_IPS)
            for _ in range(5):
                send("/api/search?q=test", headers=spoof_headers(ip))
            print(f"  🔴 Rate Limit Burst (x5 rapid)  [{ip}]")

        elif choice == 1:
            # Bot / scanner with its own spoofed IP
            agent = random.choice(bot_agents)
            ip    = random_ip(BOT_IPS)
            send("/api/search?q=test", headers=spoof_headers(ip, {"User-Agent": agent}))
            print(f"  🔴 Bot Scanner  [{ip}]  UA={agent}")

        else:
            # Command injection from a random attacker IP
            payload = random.choice(cmd_payloads)
            ip      = random_ip(ATTACKER_IPS)
            send(f"/api/search?q={payload}", headers=spoof_headers(ip))
            print(f"  🔴 Command Injection  [{ip}]  {payload}")

        time.sleep(0.3)   # fast — creates visible spikes


# =========================
# PHASE 4 — STRANGE REQUESTS (ML ANOMALY)
# =========================

def phase4_anomaly():
    banner("PHASE 4 — STRANGE REQUESTS 🤖  (ML Anomaly Detection...)")

    weird_payloads = [
        "!" * 20,
        "@" * 20,
        "$$$$$$$$$$$$$$$$$$$",
        "asdkjfhaksjdfhqwerty",
        "".join(random.choices("!@#$%^&*()_+{}[]|:;<>?", k=25)),
        "NULL" * 8,
        "\x00\x01\x02\x03\x04",
        "𝕳𝖊𝖑𝖑𝖔 𝖂𝖔𝖗𝖑𝖉",
        "SELECT" * 5,
        "A" * 500,          # oversized input
    ]

    for _ in range(20):
        payload = random.choice(weird_payloads)
        ip      = random_ip(ANOMALY_IPS)
        send(f"/api/search?q={payload}", headers=spoof_headers(ip))
        print(f"  🤖 ANOMALY  [{ip}]  {repr(payload[:40])}")
        time.sleep(0.5)


# =========================
# MAIN
# =========================

def run_simulation():
    print("\n🔥  Adaptive Firewall — 4-Phase Attack Simulation\n")

    phase1_normal_traffic()
    time.sleep(1)

    phase2_light_attacks()
    time.sleep(1)

    phase3_heavy_attacks()
    time.sleep(1)

    phase4_anomaly()

    print("\n✅  All 4 phases complete.\n")


if __name__ == "__main__":
    run_simulation()