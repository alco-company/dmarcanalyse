from __future__ import annotations

import asyncio
import csv
import gzip
import hashlib
import imaplib
import io
import ipaddress
import json
import os
import sqlite3
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Iterable
from urllib.parse import quote
import xml.etree.ElementTree as ET

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

DB_PATH = Path(os.getenv("DB_PATH", "/data/dmarc.sqlite3"))
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "CHANGE-ME-NOW")
security = HTTPBasic()
templates = Jinja2Templates(directory="app/templates")


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS reports (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          fingerprint TEXT UNIQUE NOT NULL,
          report_type TEXT NOT NULL DEFAULT 'aggregate',
          org_name TEXT, report_id TEXT, domain TEXT,
          date_begin INTEGER, date_end INTEGER,
          policy_p TEXT, policy_sp TEXT, policy_pct INTEGER,
          raw_json TEXT,
          imported_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS records (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          report_fk INTEGER NOT NULL,
          source_ip TEXT, message_count INTEGER,
          disposition TEXT, dkim_result TEXT, spf_result TEXT,
          header_from TEXT, envelope_from TEXT,
          dkim_domain TEXT, dkim_selector TEXT, dkim_auth_result TEXT,
          spf_domain TEXT, spf_scope TEXT, spf_auth_result TEXT,
          reason_type TEXT, reason_comment TEXT,
          FOREIGN KEY(report_fk) REFERENCES reports(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS import_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          source TEXT, filename TEXT, status TEXT, message TEXT,
          imported_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reports_domain ON reports(domain);
        CREATE INDEX IF NOT EXISTS idx_reports_dates ON reports(date_begin,date_end);
        CREATE INDEX IF NOT EXISTS idx_records_source ON records(source_ip);
        """)
        # Safe migrations from version 1
        cols = {r[1] for r in conn.execute("PRAGMA table_info(records)")}
        for name, typ in [("dkim_selector", "TEXT"), ("spf_scope", "TEXT"), ("reason_type", "TEXT"), ("reason_comment", "TEXT")]:
            if name not in cols:
                conn.execute(f"ALTER TABLE records ADD COLUMN {name} {typ}")
        rcols = {r[1] for r in conn.execute("PRAGMA table_info(reports)")}
        for name, definition in [("report_type", "TEXT NOT NULL DEFAULT 'aggregate'"), ("raw_json", "TEXT")]:
            if name not in rcols:
                conn.execute(f"ALTER TABLE reports ADD COLUMN {name} {definition}")


def text(node: ET.Element | None, path: str, default: str = "") -> str:
    if node is None:
        return default
    found = node.find(path)
    return (found.text or default).strip() if found is not None else default


def payloads(raw: bytes, filename: str = "upload") -> Iterable[tuple[bytes, str]]:
    low = filename.lower()
    if low.endswith(".gz") or raw[:2] == b"\x1f\x8b":
        yield gzip.decompress(raw), filename.removesuffix(".gz")
    elif low.endswith(".zip") or raw[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for name in zf.namelist():
                if name.lower().endswith((".xml", ".json")):
                    yield zf.read(name), name
    else:
        yield raw, filename


def log_import(source: str, filename: str, status_value: str, message: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO import_log(source,filename,status,message,imported_at) VALUES(?,?,?,?,?)",
            (source, filename, status_value, message, datetime.now(timezone.utc).isoformat()),
        )


def parse_aggregate(raw: bytes) -> tuple[bool, str]:
    root = ET.fromstring(raw)
    metadata = root.find("report_metadata")
    policy_node = root.find("policy_published")
    if metadata is None or policy_node is None:
        raise ValueError("Filen ligner ikke en DMARC aggregate-rapport")
    domain = text(policy_node, "domain")
    report_id = text(metadata, "report_id")
    digest = hashlib.sha256(raw).hexdigest()
    fingerprint = hashlib.sha256(f"aggregate:{digest}:{domain}:{report_id}".encode()).hexdigest()
    with db() as conn:
        try:
            cur = conn.execute("""
              INSERT INTO reports(fingerprint,report_type,org_name,report_id,domain,date_begin,date_end,policy_p,policy_sp,policy_pct,imported_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """, (
              fingerprint, "aggregate", text(metadata,"org_name"), report_id, domain,
              int(text(metadata,"date_range/begin","0") or 0), int(text(metadata,"date_range/end","0") or 0),
              text(policy_node,"p"), text(policy_node,"sp"), int(text(policy_node,"pct","100") or 100),
              datetime.now(timezone.utc).isoformat()
            ))
        except sqlite3.IntegrityError:
            return False, "Rapporten var allerede importeret"
        report_fk = cur.lastrowid
        rows = 0
        messages = 0
        for rec in root.findall("record"):
            row = rec.find("row")
            ids = rec.find("identifiers")
            auth_results = rec.find("auth_results")
            dkim = auth_results.find("dkim") if auth_results is not None else None
            spf = auth_results.find("spf") if auth_results is not None else None
            reason = row.find("policy_evaluated/reason") if row is not None else None
            count = int(text(row,"count","0") or 0)
            conn.execute("""
              INSERT INTO records(report_fk,source_ip,message_count,disposition,dkim_result,spf_result,header_from,envelope_from,
                dkim_domain,dkim_selector,dkim_auth_result,spf_domain,spf_scope,spf_auth_result,reason_type,reason_comment)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
              report_fk, text(row,"source_ip"), count,
              text(row,"policy_evaluated/disposition"), text(row,"policy_evaluated/dkim"), text(row,"policy_evaluated/spf"),
              text(ids,"header_from"), text(ids,"envelope_from"), text(dkim,"domain"), text(dkim,"selector"), text(dkim,"result"),
              text(spf,"domain"), text(spf,"scope"), text(spf,"result"), text(reason,"type"), text(reason,"comment")
            ))
            rows += 1
            messages += count
        return True, f"Importerede {rows} poster / {messages} beskeder for {domain or 'ukendt domæne'}"


def parse_tls_json(raw: bytes) -> tuple[bool, str]:
    data = json.loads(raw.decode("utf-8-sig"))
    org = data.get("organization-name", "")
    report_id = data.get("report-id", "")
    begin = data.get("date-range", {}).get("start-datetime", "")
    end = data.get("date-range", {}).get("end-datetime", "")
    domain = ""
    policies = data.get("policies") or []
    if policies:
        domain = policies[0].get("policy", {}).get("policy-domain", "")
    digest = hashlib.sha256(raw).hexdigest()
    fingerprint = hashlib.sha256(f"tls:{digest}:{report_id}".encode()).hexdigest()
    def ts(value: str) -> int:
        try: return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
        except Exception: return 0
    with db() as conn:
        try:
            conn.execute("""INSERT INTO reports(fingerprint,report_type,org_name,report_id,domain,date_begin,date_end,raw_json,imported_at)
                            VALUES(?,?,?,?,?,?,?,?,?)""",
                         (fingerprint,"tls",org,report_id,domain,ts(begin),ts(end),json.dumps(data),datetime.now(timezone.utc).isoformat()))
        except sqlite3.IntegrityError:
            return False, "TLS-rapporten var allerede importeret"
    return True, f"Importerede TLS-RPT-rapport for {domain or 'ukendt domæne'}"


def parse_and_store(raw: bytes, filename: str = "upload") -> tuple[bool, str]:
    stripped = raw.lstrip()
    if filename.lower().endswith(".json") or stripped.startswith(b"{"):
        return parse_tls_json(raw)
    return parse_aggregate(raw)


def auth(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    user_ok = hashlib.sha256(credentials.username.encode()).digest() == hashlib.sha256(ADMIN_USER.encode()).digest()
    pass_ok = hashlib.sha256(credentials.password.encode()).digest() == hashlib.sha256(ADMIN_PASSWORD.encode()).digest()
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Forkert login", headers={"WWW-Authenticate":"Basic"})
    return credentials.username


def import_imap_once() -> str:
    if os.getenv("IMAP_ENABLED", "false").lower() != "true":
        return "IMAP er deaktiveret"
    host = os.environ["IMAP_HOST"]
    port = int(os.getenv("IMAP_PORT", "993"))
    client = imaplib.IMAP4_SSL(host, port) if os.getenv("IMAP_SSL", "true").lower() == "true" else imaplib.IMAP4(host, port)
    imported = 0
    errors = 0
    try:
        client.login(os.environ["IMAP_USER"], os.environ["IMAP_PASSWORD"])
        source_folder = os.getenv("IMAP_FOLDER", "INBOX")
        archive_folder = os.getenv("IMAP_ARCHIVE_FOLDER", "")
        client.select(source_folder)
        criteria = os.getenv("IMAP_SEARCH", "UNSEEN")
        typ, data = client.search(None, criteria)
        if typ != "OK":
            return "IMAP-søgning fejlede"
        for msg_id in data[0].split():
            typ, msg_data = client.fetch(msg_id, "(RFC822)")
            if typ != "OK":
                errors += 1
                continue
            msg = BytesParser(policy=policy.default).parsebytes(msg_data[0][1])
            handled = False
            for part in msg.iter_attachments():
                name = part.get_filename() or "attachment"
                if not name.lower().endswith((".xml", ".zip", ".gz", ".json")):
                    continue
                raw = part.get_payload(decode=True) or b""
                for item, item_name in payloads(raw, name):
                    try:
                        added, message = parse_and_store(item, item_name)
                        imported += int(added)
                        handled = handled or added or "allerede" in message
                        log_import("imap", item_name, "ok", message)
                    except Exception as exc:
                        errors += 1
                        log_import("imap", item_name, "error", str(exc))
            if handled:
                if archive_folder:
                    try:
                        client.create(archive_folder)
                        client.copy(msg_id, archive_folder)
                        client.store(msg_id, "+FLAGS", "\\Deleted")
                    except Exception:
                        client.store(msg_id, "+FLAGS", "\\Seen")
                elif os.getenv("IMAP_MARK_SEEN", "true").lower() == "true":
                    client.store(msg_id, "+FLAGS", "\\Seen")
        if archive_folder:
            client.expunge()
        return f"IMAP-import: {imported} nye rapporter, {errors} fejl"
    finally:
        try: client.logout()
        except Exception: pass


async def poller() -> None:
    while True:
        try:
            await asyncio.to_thread(import_imap_once)
        except Exception as exc:
            print(f"IMAP-fejl: {exc}", flush=True)
        await asyncio.sleep(max(1, int(os.getenv("IMAP_POLL_MINUTES", "15"))) * 60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(poller())
    yield
    task.cancel()


app = FastAPI(title="DMARC Dashboard Plus", lifespan=lifespan)

@app.get("/health")
def health():
    return {"status":"ok"}


def where_clause(domain: str, days: int) -> tuple[str, list]:
    parts = ["r.report_type='aggregate'"]
    params: list = []
    if domain:
        parts.append("r.domain=?")
        params.append(domain)
    if days > 0:
        parts.append("r.date_end >= strftime('%s','now',?)")
        params.append(f"-{days} days")
    return " AND ".join(parts), params

@app.get("/", response_class=HTMLResponse)
def index(request: Request, domain: str = "", days: int = Query(30, ge=0, le=3650), _: str = Depends(auth)):
    where, params = where_clause(domain, days)
    with db() as conn:
        totals = conn.execute(f"""
          SELECT COALESCE(SUM(x.message_count),0) total,
                 COALESCE(SUM(CASE WHEN x.dkim_result='pass' OR x.spf_result='pass' THEN x.message_count ELSE 0 END),0) passed,
                 COALESCE(SUM(CASE WHEN x.dkim_result!='pass' AND x.spf_result!='pass' THEN x.message_count ELSE 0 END),0) failed,
                 COALESCE(SUM(CASE WHEN x.dkim_result='pass' THEN x.message_count ELSE 0 END),0) dkim_passed,
                 COALESCE(SUM(CASE WHEN x.spf_result='pass' THEN x.message_count ELSE 0 END),0) spf_passed,
                 COUNT(DISTINCT r.id) reports
          FROM reports r JOIN records x ON x.report_fk=r.id WHERE {where}
        """, params).fetchone()
        domains = conn.execute(f"""
          SELECT r.domain, SUM(x.message_count) messages,
            SUM(CASE WHEN x.dkim_result!='pass' AND x.spf_result!='pass' THEN x.message_count ELSE 0 END) failed,
            MAX(r.date_end) last_report
          FROM reports r JOIN records x ON x.report_fk=r.id WHERE {where}
          GROUP BY r.domain ORDER BY messages DESC
        """, params).fetchall()
        sources = conn.execute(f"""
          SELECT x.source_ip, SUM(x.message_count) messages,
            SUM(CASE WHEN x.dkim_result!='pass' AND x.spf_result!='pass' THEN x.message_count ELSE 0 END) failed,
            GROUP_CONCAT(DISTINCT x.header_from) domains,
            GROUP_CONCAT(DISTINCT x.disposition) dispositions
          FROM reports r JOIN records x ON x.report_fk=r.id WHERE {where}
          GROUP BY x.source_ip ORDER BY messages DESC LIMIT 100
        """, params).fetchall()
        trend = conn.execute(f"""
          SELECT date(r.date_end,'unixepoch') day, SUM(x.message_count) messages,
            SUM(CASE WHEN x.dkim_result!='pass' AND x.spf_result!='pass' THEN x.message_count ELSE 0 END) failed
          FROM reports r JOIN records x ON x.report_fk=r.id WHERE {where}
          GROUP BY day ORDER BY day
        """, params).fetchall()
        dispositions = conn.execute(f"""
          SELECT COALESCE(x.disposition,'none') name, SUM(x.message_count) messages
          FROM reports r JOIN records x ON x.report_fk=r.id WHERE {where}
          GROUP BY name ORDER BY messages DESC
        """, params).fetchall()
        all_domains = conn.execute("SELECT DISTINCT domain FROM reports WHERE report_type='aggregate' AND domain!='' ORDER BY domain").fetchall()
        recent = conn.execute("SELECT source,filename,status,message,imported_at FROM import_log ORDER BY id DESC LIMIT 10").fetchall()
        tls_count = conn.execute("SELECT COUNT(*) FROM reports WHERE report_type='tls'").fetchone()[0]
    return templates.TemplateResponse("index.html", {
        "request":request,"totals":totals,"domains":domains,"sources":sources,
        "trend":trend,"dispositions":dispositions,"all_domains":all_domains,"selected_domain":domain,"days":days,
        "recent":recent,"tls_count":tls_count,"imap_enabled":os.getenv("IMAP_ENABLED","false").lower()=="true"
    })

@app.post("/upload")
async def upload(file: UploadFile = File(...), _: str = Depends(auth)):
    raw = await file.read()
    messages = []
    try:
        for item, item_name in payloads(raw, file.filename or "upload"):
            _, message = parse_and_store(item, item_name)
            messages.append(message)
            log_import("upload", item_name, "ok", message)
    except Exception as exc:
        log_import("upload", file.filename or "upload", "error", str(exc))
        raise HTTPException(400, f"Kunne ikke læse rapporten: {exc}")
    return RedirectResponse(url="/?msg=" + quote(" | ".join(messages)), status_code=303)

@app.post("/imap-now")
async def imap_now(_: str = Depends(auth)):
    message = await asyncio.to_thread(import_imap_once)
    return RedirectResponse(url="/?msg=" + quote(message), status_code=303)

@app.get("/report/{report_id}", response_class=HTMLResponse)
def report_detail(report_id: int, request: Request, _: str = Depends(auth)):
    with db() as conn:
        report = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not report:
            raise HTTPException(404, "Rapporten findes ikke")
        records = conn.execute("SELECT * FROM records WHERE report_fk=? ORDER BY message_count DESC", (report_id,)).fetchall()
    return templates.TemplateResponse("report.html", {"request":request,"report":report,"records":records})

@app.get("/reports", response_class=HTMLResponse)
def reports_list(request: Request, _: str = Depends(auth)):
    with db() as conn:
        rows = conn.execute("SELECT id,report_type,org_name,report_id,domain,date_begin,date_end,policy_p,imported_at FROM reports ORDER BY date_end DESC,id DESC LIMIT 500").fetchall()
    return templates.TemplateResponse("reports.html", {"request":request,"reports":rows})

@app.get("/export.csv")
def export_csv(domain: str = "", days: int = Query(30, ge=0, le=3650), _: str = Depends(auth)):
    where, params = where_clause(domain, days)
    with db() as conn:
        rows = conn.execute(f"""
          SELECT r.domain,r.org_name,r.report_id,datetime(r.date_begin,'unixepoch') date_begin,
                 datetime(r.date_end,'unixepoch') date_end,x.source_ip,x.message_count,x.disposition,
                 x.dkim_result,x.spf_result,x.header_from,x.envelope_from,x.dkim_domain,x.dkim_selector,
                 x.dkim_auth_result,x.spf_domain,x.spf_scope,x.spf_auth_result,x.reason_type,x.reason_comment
          FROM reports r JOIN records x ON x.report_fk=r.id WHERE {where}
          ORDER BY r.date_end DESC,x.message_count DESC
        """, params).fetchall()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(rows[0].keys() if rows else ["domain","org_name","report_id"])
    for row in rows:
        writer.writerow(list(row))
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv; charset=utf-8", headers={"Content-Disposition":"attachment; filename=dmarc-export.csv"})
