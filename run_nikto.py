#!/usr/bin/env python3

import os
import re
import sys
import json
import time
import html
import ssl
import mimetypes
import threading
import subprocess
from datetime import datetime
from typing import List, Dict, Any
from email.message import EmailMessage
import smtplib
from openai import OpenAI

TARGET = "https://example.com"
REPORT_DIR = "/path/to/report/"
NIKTO_BIN = "/usr/bin/nikto"
TIMEOUT_SECONDS = 4 * 60 * 60
SHOW_LAST_LOG_LINES = 30

SMTP_CONFIG = {
    "server": "",
    "port": 25,
    "use_ssl": False,
    "starttls": False,
    "username": None,
    "password": None,
    "from_addr": "",
    "to_addr": "",
}

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
if not OPENROUTER_API_KEY:
    print("Missing OPENROUTER_API_KEY")
    sys.exit(1)

MODEL_NAME = "deepseek/deepseek-chat-v3.1:free"
BASE_URL = "https://openrouter.ai/api/v1"
DELAY_BETWEEN_CALLS = 0.6

nikto_find_re = re.compile(r"^\+ (.+)$", re.MULTILINE)

THREAT_KEYWORDS = [
    "osvdb-", "sql injection", "xss", "cross-site", "directory index",
    "remote file", "rfi", "lfi", "command execution", "sensitive",
    "credentials", "exposed", "backup", "config", "admin", "file upload",
    "upload", "injection", "information disclosure", "leak", "vulnerab",
    "outdated", "weak", "allowed methods", "server-status", "phpinfo",
    "open directory", "clickjacking", "csrf", "authentication bypass"
]

NOISE_PATTERNS = [
    r"^start time", r"^end time", r"^target", r"^scan started", r"^server:", r"^retrieved",
    r"^banner", r"^nikto", r"^http server", r"^timeout", r"^ssl info", r"^ssl\-",
    r"^port", r"^timestamp", r"^host:"
]
NOISE_RE = re.compile("|".join(NOISE_PATTERNS), re.IGNORECASE)

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def tail_lines(path, n=SHOW_LAST_LOG_LINES):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            return lines[-n:]
    except Exception:
        return []

def try_run_nikto(cmd, env, log_file, timeout):
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
            env=env
        )
    except Exception:
        return None, 4

    def feed_no(p):
        try:
            try:
                p.stdin.write("n\n")
                p.stdin.flush()
            except Exception:
                pass
            while p.poll() is None:
                try:
                    p.stdin.write("n\n")
                    p.stdin.flush()
                except Exception:
                    pass
                time.sleep(2)
        except Exception:
            pass
        finally:
            try:
                p.stdin.close()
            except Exception:
                pass

    feeder = threading.Thread(target=feed_no, args=(proc,), daemon=True)
    feeder.start()

    ret = None
    with open(log_file, "w", encoding="utf-8", errors="replace") as lf:
        try:
            for raw_line in proc.stdout:
                line = raw_line.rstrip("\n")
                lf.write(line + "\n")
                lf.flush()
                print(f"[nikto] {line}")
            proc.wait()
            ret = proc.returncode
        except KeyboardInterrupt:
            lf.write("\n[INFO] Interrupted\n")
            try:
                proc.kill()
            except Exception:
                pass
            return proc, 5
        except Exception as e:
            lf.write(f"\n[EXCEPTION] {e}\n")
            try:
                proc.kill()
            except Exception:
                pass
            return proc, 4
    return proc, ret

def run_nikto(target, report_dir, timeout):
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_html = os.path.join(report_dir, f"nikto_report_{ts}.html")
    report_txt = os.path.join(report_dir, f"nikto_report_{ts}.txt")
    log_file = os.path.join(report_dir, f"nikto_{ts}.log")

    cmd_candidates = [
        [NIKTO_BIN, "-h", target, "-o", report_html, "-Format", "html", "-nointeractive"],
        [NIKTO_BIN, "-h", target, "-o", report_html, "-F", "html", "-nointeractive"],
        [NIKTO_BIN, "-h", target, "-o", report_txt, "-nointeractive"],
    ]

    env = os.environ.copy()
    env.pop('PERL5OPT', None)

    proc = None
    ret = None

    for cmd in cmd_candidates:
        proc, ret = try_run_nikto(cmd, env, log_file, timeout)
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as lf:
                content = lf.read(1000)
        except Exception:
            content = ""
        if ("unrecognized" in content.lower() or ("usage:" in content.lower() and "nikto" in content.lower())) and ret != 0:
            continue
        else:
            break

    chosen_report = report_html if os.path.exists(report_html) else report_txt
    return ret, chosen_report, log_file

def attach_file_to_message(msg: EmailMessage, path: str):
    if not path or not os.path.isfile(path):
        return
    ctype, encoding = mimetypes.guess_type(path)
    if ctype is None or encoding is not None:
        ctype = 'application/octet-stream'
    maintype, subtype = ctype.split('/', 1)
    with open(path, 'rb') as f:
        data = f.read()
    msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=os.path.basename(path))

def send_email(smtp_cfg, subject, body, attachments=None):
    attachments = attachments or []
    msg = EmailMessage()
    msg['From'] = smtp_cfg.get('from_addr') or smtp_cfg.get('username') or "nikto@localhost"
    msg['To'] = smtp_cfg.get('to_addr')
    msg['Subject'] = subject
    msg.set_content(body)

    for path in attachments:
        attach_file_to_message(msg, path)

    server = None
    try:
        if smtp_cfg.get('use_ssl', False):
            server = smtplib.SMTP_SSL(smtp_cfg['server'], smtp_cfg['port'], context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(smtp_cfg['server'], smtp_cfg['port'], timeout=30)
            if smtp_cfg.get('starttls', False):
                server.starttls(context=ssl.create_default_context())

        username = smtp_cfg.get('username')
        password = smtp_cfg.get('password')
        if username and password:
            server.login(username, password)

        server.send_message(msg)
        return True
    except Exception:
        return False
    finally:
        try:
            if server:
                server.quit()
        except Exception:
            pass

def is_threat_line(line: str, strict: bool = False) -> bool:
    s = line.strip()
    if not s:
        return False
    if NOISE_RE.search(s):
        return False
    if re.search(r"ID:\s*\d+\s*—\s*CVSS:\s*CVSS:\d+\.\d+\/[A-Z:\/]+", s):
        return False
    lower = s.lower()
    if "osvdb-" in lower:
        return True
    has_path = bool(re.search(r"(/\S+)", s))
    has_keyword = any(k in lower for k in THREAT_KEYWORDS)
    if strict:
        return ("osvdb-" in lower) or (has_path and has_keyword)
    else:
        if has_keyword:
            return True
        if has_path and not lower.startswith("server") and not lower.startswith("retrieved"):
            if not re.match(r"server[:\s]", lower):
                return True
    return False

def extract_findings_from_log(text: str, strict: bool = False) -> List[str]:
    findings = []
    for m in nikto_find_re.finditer(text):
        line = m.group(1).strip()
        if is_threat_line(line, strict=strict):
            findings.append(line)
    if not findings:
        candidate_blocks = re.split(r"\n\s*\n", text)
        for block in candidate_blocks:
            block = block.strip()
            if len(block) < 30:
                continue
            low = block.lower()
            if "osvdb-" in low or any(k in low for k in THREAT_KEYWORDS):
                findings.append(" ".join(block.splitlines()))
    dedup = []
    seen = set()
    for f in findings:
        key = f[:400]
        if key not in seen:
            dedup.append(f)
            seen.add(key)
    return dedup

def make_client() -> OpenAI:
    client = OpenAI(api_key=OPENROUTER_API_KEY, base_url=BASE_URL)
    return client

def call_openrouter_analyze(client: OpenAI, finding_text: str, context_info: str = "") -> Dict[str, Any]:
    prompt_system = {
    "role": "system",
    "content": (
        "You are a security assistant specialized in analyzing Nikto reports. "
        "For each finding provided, respond ONLY with a valid JSON object (no extra text) "
        "with the following fields: id, title, severity (0-10), cvss, description, impact, remediation, references (list), raw_text. "
        "Write in English. If a value is unknown, use an empty string or empty list."
	    )
	}

prompt_user = {
    "role": "user",
    "content": (
        f"Here is the Nikto finding:\n\n\"\"\"\n{finding_text}\n\"\"\"\n\nContext: {context_info}\n\n"
        "STRICTLY produce a valid JSON object."
	    )
	}


    completion = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[prompt_system, prompt_user],
        temperature=0.0,
        max_tokens=800,
        top_p=1.0,
        n=1,
        extra_headers={},
        extra_body={}
    )

    try:
        content = completion.choices[0].message.content
    except Exception:
        return {
            "id": "",
            "title": "",
            "severity": 0,
            "cvss": "",
            "description": "Incomplete or unexpected model response.",
            "impact": "",
            "remediation": "",
            "references": [],
            "raw_text": finding_text
        }

    try:
        s = content.strip()
        first_brace = s.find("{")
        last_brace = s.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            candidate = s[first_brace:last_brace+1]
            json_obj = json.loads(candidate)
        else:
            json_obj = json.loads(s)
    except Exception as e:
        json_obj = {
            "id": "",
            "title": "",
            "severity": 0,
            "cvss": "",
            "description": f"Model parsing error: {str(e)}. Raw content: {content[:800]}",
            "impact": "",
            "remediation": "",
            "references": [],
            "raw_text": finding_text
        }

    return json_obj

def normalize_severity(value) -> int:
    try:
        if isinstance(value, (int, float)):
            v = int(round(value))
        else:
            v = int(float(re.sub(r"[^\d\.]", "", str(value) or "0")))
    except Exception:
        v = 0
    if v < 0:
        v = 0
    if v > 10:
        v = 10
    return v

def generate_html_report(report_items: List[Dict[str, Any]], output_path: str, metadata: Dict[str, str]):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    title = html.escape(metadata.get("title", "Report"))
    host = html.escape(metadata.get("host", ""))
    css = (
        "body{font-family:Inter, ui-sans-serif, system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial; background:#f6f8fb; color:#0f172a; padding:30px;} "
        ".container{max-width:1000px;margin:0 auto;background:white;border-radius:12px;padding:28px;box-shadow:0 10px 30px rgba(15,23,42,0.07);} "
        "h1{margin:0 0 8px;font-size:24px;} .meta{color:#475569;font-size:13px;margin-bottom:18px;} "
        ".item{border:1px solid #e6eef8;border-left:6px solid #dbeafe;padding:16px;border-radius:8px;margin-bottom:12px;background:linear-gradient(180deg, rgba(255,255,255,0.8), rgba(250,252,255,0.8));} "
        ".sev{font-weight:700;padding:6px 8px;border-radius:6px;color:white;display:inline-block;font-size:13px;} "
        ".sev-10{background:#7f1d1d;} .sev-8{background:#b91c1c;} .sev-6{background:#ea580c;} .sev-4{background:#f59e0b;} .sev-2{background:#16a34a;} .sev-0{background:#6b7280;} "
        ".title{font-size:18px;margin:0 0 6px;} .section{margin-top:8px;font-size:14px;} "
        ".pre{background:#0f172a;color:#f8fafc;padding:10px;border-radius:6px;overflow:auto;font-family:monospace;font-size:13px;} "
        ".references a{color:#2563eb;} .toc{margin-bottom:14px;} "
        ".toc a{display:inline-block;margin-right:10px;padding:6px 10px;background:#f1f5f9;border-radius:999px;color:#0f172a;font-size:13px;text-decoration:none;border:1px solid #e2e8f0;} "
        "footer{font-size:12px;color:#64748b;margin-top:20px;}"
    )

    items_html = []
    for it in report_items:
        sev = normalize_severity(it.get("severity", 0))
        sev_class = (
            "sev-10" if sev >= 9
            else "sev-8" if sev >= 7
            else "sev-6" if sev >= 5
            else "sev-4" if sev >= 3
            else "sev-2" if sev >= 1
            else "sev-0"
        )
        refs = it.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        refs_html = ""
        if refs:
            refs_html = "<ul>" + "".join(
                f'<li><a href="{html.escape(r)}" target="_blank" rel="noopener">{html.escape(r)}</a></li>'
                for r in refs
            ) + "</ul>"
        items_html.append(f"""
        <div class="item" id="{html.escape(it.get('id',''))}">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <div class="title">{html.escape(it.get('title') or 'No title')}</div>
              <div class="meta">ID: {html.escape(it.get('id') or '')} — CVSS: {html.escape(it.get('cvss') or '')}</div>
            </div>
            <div style="text-align:right">
              <div class="sev {sev_class}">Severity: {sev}/10</div>
              <div style="margin-top:6px;font-size:12px;color:#475569">Impact: {html.escape(it.get('impact') or '')[:160]}</div>
            </div>
          </div>
          <div class="section"><strong>Description</strong><div class="pre">{html.escape(it.get('description') or '')}</div></div>
          <div class="section"><strong>Remediation</strong><div class="pre">{html.escape(it.get('remediation') or '')}</div></div>
          <div class="section references"><strong>References</strong>{refs_html}</div>
          <div class="section"><strong>Raw text</strong><div class="pre">{html.escape(it.get('raw_text') or '')}</div></div>
        </div>
        """)

    toc_html = "".join(
        f'<a href="#{html.escape(it.get("id",""))}">{html.escape(it.get("title") or it.get("id",""))} ({normalize_severity(it.get("severity",0))})</a>'
        for it in report_items
    )

    html_full = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title} - Report</title>
<style>{css}</style>
</head>
<body>
  <div class="container">
    <h1>{title}</h1>
    <div class="meta">Generated: {now} · Items: {len(report_items)}</div>
    <div class="toc"><strong>Summary:</strong> {toc_html}</div>
    {"".join(items_html)}
    <footer>Generated via AI model {MODEL_NAME}</footer>
  </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_full)
    print(f"Report saved: {output_path}")

def main():
    ensure_dir(REPORT_DIR)
    ret, report_path, log_path = run_nikto(TARGET, REPORT_DIR, TIMEOUT_SECONDS)
    if log_path and os.path.isfile(log_path):
        for l in tail_lines(log_path, SHOW_LAST_LOG_LINES):
            print(l.rstrip())
    if not os.path.isfile(log_path):
        sys.exit(1)
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    findings = extract_findings_from_log(text, strict=False)
    if not findings:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        subject = f"[Nikto] No critical results — {now}"
        body = f"Nikto scan completed. No relevant findings.\n\nLog: {log_path}"
        send_email(SMTP_CONFIG, subject, body, attachments=[log_path])
        sys.exit(0)
    client = make_client()
    analyzed_items = []
    for idx, ftext in enumerate(findings, start=1):
        try:
            obj = call_openrouter_analyze(client, ftext, context_info=f"Item {idx}")
            obj.setdefault("id", f"FIND-{idx:03d}")
            obj.setdefault("title", ftext[:80])
            obj.setdefault("severity", obj.get("severity", 0))
            obj.setdefault("cvss", obj.get("cvss", ""))
            obj.setdefault("description", obj.get("description", ""))
            obj.setdefault("impact", obj.get("impact", ""))
            obj.setdefault("remediation", obj.get("remediation", ""))
            obj.setdefault("references", obj.get("references", []))
            obj.setdefault("raw_text", ftext)
            obj["severity"] = normalize_severity(obj.get("severity", 0))
            analyzed_items.append(obj)
        except Exception:
            analyzed_items.append({
                "id": f"FIND-{idx:03d}",
                "title": ftext[:80],
                "severity": 0,
                "cvss": "",
                "description": "AI analysis error",
                "impact": "",
                "remediation": "",
                "references": [],
                "raw_text": ftext
            })
        time.sleep(DELAY_BETWEEN_CALLS)
    analyzed_items.sort(key=lambda x: x.get("severity", 0), reverse=True)
    base = os.path.splitext(log_path)[0]
    ia_report_html = base + "_ia_report.html"
    metadata = {"title": "Nikto Analysis", "host": ""}
    generate_html_report(analyzed_items, ia_report_html, metadata)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = f"[Nikto IA] Report — {now}"
    body = f"Please find attached the AI‑analyzed report for target {TARGET}."
    send_email(SMTP_CONFIG, subject, body, attachments=[ia_report_html])
    if report_path and os.path.isfile(report_path):
        print(f"Original report: {report_path}")
    print(f"AI report generated: {ia_report_html}")
    print(f"Log file: {log_path}")

if __name__ == "__main__":
    main()
