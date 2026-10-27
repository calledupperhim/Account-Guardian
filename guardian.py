#!/usr/bin/env python3
"""Account Guardian - local, open-source (MIT) sign-in alert scanner.

Reads security-alert emails in your inbox (read-only IMAP), extracts the IP /
device / location of each sign-in, geolocates the IP, and helps you secure
the affected account. Python standard library only. Runs on 127.0.0.1.
Your email password is kept in memory only and never written to disk.
"""
import imaplib, email, re, json, ipaddress, secrets, hashlib, webbrowser
import urllib.request, urllib.parse, sys
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime, parseaddr
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = 8765
TOKEN = secrets.token_urlsafe(16)
STORE = Path.home() / ".account_guardian.json"  # only stores "It was me" IDs
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()

IMAP_HOSTS = {
    "gmail.com": "imap.gmail.com", "googlemail.com": "imap.gmail.com",
    "outlook.com": "outlook.office365.com", "hotmail.com": "outlook.office365.com",
    "live.com": "outlook.office365.com", "yahoo.com": "imap.mail.yahoo.com",
    "icloud.com": "imap.mail.me.com", "me.com": "imap.mail.me.com",
    "proton.me": "127.0.0.1",  # needs Proton Bridge
}

# domain -> (name, "active sessions / sign out" page, security settings page)
SERVICES = {
    "google.com": ("Google", "https://myaccount.google.com/device-activity", "https://myaccount.google.com/security-checkup"),
    "microsoft.com": ("Microsoft", "https://account.live.com/Activity", "https://account.microsoft.com/security"),
    "github.com": ("GitHub", "https://github.com/settings/sessions", "https://github.com/settings/security"),
    "facebook.com": ("Facebook", "https://www.facebook.com/settings?tab=security", "https://www.facebook.com/settings?tab=security"),
    "instagram.com": ("Instagram", "https://accountscenter.instagram.com/password_and_security/", "https://accountscenter.instagram.com/password_and_security/"),
    "x.com": ("X / Twitter", "https://x.com/settings/sessions", "https://x.com/settings/security"),
    "linkedin.com": ("LinkedIn", "https://www.linkedin.com/psettings/sessions", "https://www.linkedin.com/psettings/sign-in-and-security"),
    "apple.com": ("Apple", "https://account.apple.com/account/manage", "https://account.apple.com/account/manage"),
    "dropbox.com": ("Dropbox", "https://www.dropbox.com/account/security", "https://www.dropbox.com/account/security"),
    "paypal.com": ("PayPal", "https://www.paypal.com/myaccount/security", "https://www.paypal.com/myaccount/security"),
    "netflix.com": ("Netflix", "https://www.netflix.com/account", "https://www.netflix.com/account"),
    "spotify.com": ("Spotify", "https://www.spotify.com/account/overview/", "https://www.spotify.com/account/overview/"),
    "slack.com": ("Slack", "https://slack.com/account/sessions", "https://slack.com/account/settings"),
    "yahoo.com": ("Yahoo", "https://login.yahoo.com/account/activity", "https://login.yahoo.com/account/security"),
    "reddit.com": ("Reddit", "https://www.reddit.com/settings/security", "https://www.reddit.com/settings/security"),
}
ALIASES = {"facebookmail.com": "facebook.com", "microsoftonline.com": "microsoft.com",
           "live.com": "microsoft.com", "twitter.com": "x.com", "googlemail.com": "google.com",
           "accountprotection.microsoft.com": "microsoft.com"}

ALERT_RE = re.compile(
    r"(new|unusual|suspicious|unrecogni[sz]ed|recent).{0,25}(sign|log)[- ]?(in|on)|security alert|"
    r"new device|new login|login attempt|someone (tried|else)|was used to sign in|"
    r"password (was )?(changed|reset)|critical security|verify it.?s you|sign-in (was )?blocked", re.I)
ACCOUNT_RE = re.compile(
    r"welcome|verify your e-?mail|confirm your (e-?mail|account)|thanks for (signing|joining)|"
    r"activate your account|your account|account created|your receipt|your order", re.I)

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.I)
LOC = re.compile(r"(?:Approximate location|Location|Near|Where)\s*[:\-]\s*([^\r\n<]{3,70})", re.I)
DEV = re.compile(r"(?:Device|Browser|Operating system|Platform)\s*[:\-]\s*([^\r\n<]{3,70})", re.I)
GEO_CACHE = {}


def reg_domain(addr):
    d = addr.split("@")[-1].lower().strip(">")
    parts = d.split(".")
    if len(parts) >= 3 and parts[-1] != "com" and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
        d = ".".join(parts[-3:])
    else:
        d = ".".join(parts[-2:])
    return ALIASES.get(d, d)


def service_info(domain):
    if domain in SERVICES:
        n, s, c = SERVICES[domain]
    else:
        q = lambda t: "https://www.google.com/search?q=" + urllib.parse.quote(f"{domain} {t}")
        n, s, c = domain, q("sign out of all devices"), q("secure my account")
    return {"name": n, "domain": domain, "sessions": s, "security": c,
            "report": "https://www.google.com/search?q=" + urllib.parse.quote(f"report hacked {n} account")}


def dec(v):
    try:
        return str(make_header(decode_header(v or "")))
    except Exception:
        return v or ""


def body_text(msg):
    plain, html = "", ""
    for p in msg.walk():
        ct = p.get_content_type()
        if ct not in ("text/plain", "text/html"):
            continue
        try:
            t = p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8", "replace")
        except Exception:
            continue
        if ct == "text/plain":
            plain += t
        else:
            html += re.sub(r"<(br|/p|/div|/tr|/li)[^>]*>", "\n", t, flags=re.I)
    text = plain or re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"[ \t\xa0]+", " ", text)[:30000]


def public_ips(text):
    out = []
    for m in IPV4.findall(text) + IPV6.findall(text):
        try:
            ip = ipaddress.ip_address(m)
            if ip.is_global and m not in out:
                out.append(m)
        except ValueError:
            pass
    return out


def geo(ip):
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    res = None
    try:  # ip-api.com free tier (HTTP only, ~45 req/min). Only the IP is sent.
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,proxy,hosting,lat,lon"
        with urllib.request.urlopen(url, timeout=8) as r:
            j = json.load(r)
        if j.get("status") == "success":
            res = j
    except Exception:
        pass
    GEO_CACHE[ip] = res
    return res


def scan(addr, pw, host, days):
    host = host or IMAP_HOSTS.get(addr.split("@")[-1].lower())
    if not host:
        raise ValueError("Unknown mail provider - enter the IMAP server manually.")
    try:
        M = imaplib.IMAP4_SSL(host, timeout=30)
        M.login(addr, pw)
    except imaplib.IMAP4.error:
        raise ValueError("Login failed. Gmail/Yahoo/iCloud need an *app password*, and IMAP must be enabled.")
    alerts_meta, accounts = [], {}
    try:
        M.select("INBOX", readonly=True)
        s = datetime.now() - timedelta(days=days)
        _, data = M.search(None, "SINCE", f"{s.day:02d}-{MONTHS[s.month - 1]}-{s.year}")
        ids = data[0].split()[-2500:]
        for i in range(0, len(ids), 200):
            _, resp = M.fetch(b",".join(ids[i:i + 200]),
                              "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)])")
            for it in resp:
                if not isinstance(it, tuple):
                    continue
                h = email.message_from_bytes(it[1])
                subj, frm = dec(h.get("Subject")), parseaddr(h.get("From", ""))[1]
                is_alert, is_acct = ALERT_RE.search(subj), ACCOUNT_RE.search(subj)
                if not (is_alert or is_acct) or not frm:
                    continue
                dom = reg_domain(frm)
                try:
                    date = parsedate_to_datetime(h.get("Date")).isoformat()
                except Exception:
                    date = ""
                a = accounts.setdefault(dom, {"count": 0, "last": ""})
                a["count"] += 1
                a["last"] = max(a["last"], date)
                if is_alert:
                    alerts_meta.append((it[0].split()[0], subj, dom, date, h.get("Message-ID", subj + date)))
        alerts = []
        for num, subj, dom, date, mid in alerts_meta[-60:]:
            _, r = M.fetch(num, "(BODY.PEEK[])")
            msg = email.message_from_bytes(r[0][1])
            text = body_text(msg)
            ips = public_ips(text)
            lm, dm = LOC.search(text), DEV.search(text)
            g = geo(ips[0]) if ips else None
            alerts.append({
                "id": hashlib.sha1(mid.encode()).hexdigest()[:16], "subject": subj, "date": date,
                "svc": service_info(dom), "ip": ips[0] if ips else None, "geo": g,
                "mail_location": lm.group(1).strip() if lm else None,
                "device": dm.group(1).strip() if dm else None,
            })
        alerts.sort(key=lambda a: a["date"], reverse=True)
        accs = [dict(service_info(d), **v) for d, v in accounts.items()]
        accs.sort(key=lambda a: -a["count"])
        return {"alerts": alerts, "accounts": accs, "scanned": len(ids), "dismissed": load_dismissed()}
    finally:
        try:
            M.logout()
        except Exception:
            pass


def load_dismissed():
    try:
        return json.loads(STORE.read_text())
    except Exception:
        return []


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Account Guardian</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--tx:#14181f;--mu:#667085;--bd:#e4e7ec;--ac:#2563eb;--rd:#d92d20;--gr:#12b76a}
@media(prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#171b22;--tx:#e8ecf2;--mu:#98a2b3;--bd:#2a313c;--ac:#6ea0ff;--rd:#f97066;--gr:#32d583}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:24px 16px 60px}h1{margin:0 0 4px;font-size:26px}h2{margin:28px 0 10px;font-size:18px}
.mu{color:var(--mu)}.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px 16px;margin:10px 0}
.card.warn{border-left:4px solid var(--rd)}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.sp{justify-content:space-between}
input{width:100%;padding:9px 10px;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--tx);font:inherit}
label{font-size:13px;color:var(--mu);display:block;margin:8px 0 3px}.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
button,a.b{padding:8px 13px;border-radius:8px;border:1px solid var(--bd);background:var(--card);color:var(--tx);font:inherit;cursor:pointer;text-decoration:none;display:inline-block}
.pri{background:var(--ac);color:#fff;border-color:var(--ac)}.dan{background:var(--rd);color:#fff;border-color:var(--rd)}
.tag{font-size:12px;padding:2px 8px;border-radius:99px;border:1px solid var(--bd)}.tag.r{color:var(--rd);border-color:var(--rd)}
#modal{position:fixed;inset:0;background:#0008;display:none;align-items:center;justify-content:center;padding:16px}
#modal .card{max-width:520px;width:100%;max-height:90vh;overflow:auto}ol{padding-left:20px}li{margin:6px 0}
@media(max-width:600px){.g2{grid-template-columns:1fr}}
</style></head><body><main>
<h1>🛡️ Account Guardian</h1>
<div class="mu">Runs only on your computer. Read-only mailbox access. Password kept in memory, never saved.</div>
<div class="card"><div class="g2"><div><label>Email address</label><input id="em" type="email" placeholder="you@gmail.com"></div>
<div><label>App password (not your normal password)</label><input id="pw" type="password"></div>
<div><label>IMAP server (auto-detected if blank)</label><input id="host" placeholder="imap.gmail.com"></div>
<div><label>Days to scan</label><input id="days" type="number" value="90" min="1" max="365"></div></div>
<div class="row" style="margin-top:12px"><button class="pri" id="go">Scan my inbox</button><span id="st" class="mu"></span></div></div>
<div id="out"></div>
<div id="modal"><div class="card" id="mc"></div></div>
</main><script>
const T="__TOKEN__",$=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function api(p,b){const r=await fetch(p,{method:"POST",headers:{"Content-Type":"application/json","X-Token":T},body:JSON.stringify(b)});const j=await r.json();if(!r.ok)throw new Error(j.error||"Error");return j}
let D=null,hidden=new Set();
$("#go").onclick=async()=>{$("#st").textContent="Scanning… this can take a minute";$("#go").disabled=true;
try{D=await api("/api/scan",{email:$("#em").value.trim(),password:$("#pw").value,host:$("#host").value.trim(),days:+$("#days").value||90});
hidden=new Set(D.dismissed);$("#st").textContent=`Scanned ${D.scanned} emails.`;render()}catch(e){$("#st").textContent="⚠️ "+e.message}
$("#go").disabled=false};
function where(a){const g=a.geo;if(!g)return a.mail_location?esc(a.mail_location)+" <span class='mu'>(from email)</span>":"<span class='mu'>No IP found in this email</span>";
const p=[g.city,g.regionName,g.country].filter(Boolean).join(", ");
return `<b>${esc(p)}</b> · ${esc(g.isp)} <a href="https://www.openstreetmap.org/?mlat=${g.lat}&mlon=${g.lon}#map=10/${g.lat}/${g.lon}" target="_blank" rel="noopener">map</a>`}
function render(){const al=D.alerts.filter(a=>!hidden.has(a.id));
let h=`<h2>Sign-in alerts (${al.length})</h2><div class="mu">Locations come from IP lookups: accurate to roughly city level, and VPNs distort them.</div>`;
if(!al.length)h+=`<div class="card">No unreviewed alerts found 🎉</div>`;
al.forEach(a=>{const g=a.geo,flag=g&&(g.proxy||g.hosting);
h+=`<div class="card warn"><div class="row sp"><b>${esc(a.svc.name)}</b><span class="mu">${esc(a.date.slice(0,16).replace("T"," "))}</span></div>
<div>${esc(a.subject)}</div><div style="margin:6px 0">📍 ${where(a)}${a.ip?` · <code>${esc(a.ip)}</code>`:""}${a.device?` · 💻 ${esc(a.device)}`:""}
${flag?` <span class="tag r">VPN/proxy/datacenter</span>`:""}</div>
<div class="row"><button onclick="ok('${a.id}')">✅ It was me</button><button class="dan" onclick="notme('${a.id}')">🚨 Not me</button></div></div>`});
h+=`<h2>Accounts found linked to this email (${D.accounts.length})</h2><div class="mu">Detected from welcome, verification and alert emails. Check each one's active sessions.</div>`;
D.accounts.forEach(s=>{h+=`<div class="card row sp"><div><b>${esc(s.name)}</b> <span class="mu">${esc(s.domain)} · ${s.count} emails</span></div>
<div class="row"><a class="b" target="_blank" rel="noopener" href="${esc(s.sessions)}">View sessions / sign out</a><a class="b" target="_blank" rel="noopener" href="${esc(s.security)}">Security</a></div></div>`});
$("#out").innerHTML=h}
async function ok(id){hidden.add(id);await api("/api/dismiss",{id});render()}
function notme(id){const a=D.alerts.find(x=>x.id==id),s=a.svc;
$("#mc").innerHTML=`<h2 style="margin-top:0">Secure your ${esc(s.name)} account</h2>
<p class="mu">Websites don't allow outside apps to kick a session, so do it in this order on ${esc(s.name)}'s own pages:</p><ol>
<li><a target="_blank" rel="noopener" href="${esc(s.sessions)}"><b>Sign out all other devices / sessions</b></a></li>
<li>Change the password now (unique, from a password manager), and on any site where you reused it.</li>
<li><a target="_blank" rel="noopener" href="${esc(s.security)}">Turn on 2-step verification / passkeys</a></li>
<li>Remove unknown connected apps, recovery emails/phones and mail-forwarding rules.</li>
<li>Check your email account itself the same way, since it can reset all the others.</li></ol>
<div class="row"><a class="b dan" target="_blank" rel="noopener" href="${esc(s.report)}">Report to ${esc(s.name)}</a></div>
<label>Report to authorities (pick your country)</label><div class="row">
<a class="b" target="_blank" rel="noopener" href="https://cybercrime.gov.in">India</a>
<a class="b" target="_blank" rel="noopener" href="https://www.ic3.gov">USA</a>
<a class="b" target="_blank" rel="noopener" href="https://www.actionfraud.police.uk">UK</a></div>
<div class="row" style="margin-top:14px"><button onclick="$('#modal').style.display='none'">Close</button></div>`;
$("#modal").style.display="flex"}
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def _host_ok(self):
        return self.headers.get("Host", "") in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")

    def do_GET(self):
        if self.path != "/" or not self._host_ok():
            return self._send(404, "not found", "text/plain")
        self._send(200, PAGE.replace("__TOKEN__", TOKEN), "text/html")

    def do_POST(self):
        if not self._host_ok() or self.headers.get("X-Token") != TOKEN:
            return self._send(403, json.dumps({"error": "forbidden"}))
        try:
            d = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if self.path == "/api/scan":
                if not d.get("email") or not d.get("password"):
                    raise ValueError("Enter your email and app password.")
                res = scan(d["email"], d["password"], d.get("host", ""), max(1, min(int(d.get("days", 90)), 365)))
                return self._send(200, json.dumps(res))
            if self.path == "/api/dismiss":
                s = set(load_dismissed()) | {str(d.get("id"))}
                STORE.write_text(json.dumps(sorted(s)))
                return self._send(200, "{}")
            self._send(404, json.dumps({"error": "not found"}))
        except ValueError as e:
            self._send(400, json.dumps({"error": str(e)}))
        except Exception as e:
            self._send(500, json.dumps({"error": f"{type(e).__name__}: {e}"}))


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    url = f"http://127.0.0.1:{PORT}"
    print(f"Account Guardian running at {url}  (Ctrl+C to stop)")
    webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
