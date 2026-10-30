"""Core Student Support Agent: manual tool registry, ReAct-style loop, memory, retrieval and safety."""
import os, re, json, sqlite3, hashlib, secrets, time, uuid, csv
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("STUDENT_AGENT_DB", ROOT / "student_support.db"))
POLICY_TEXT = """# Demonstration Student Handbook\n\n## Fee Payment\nIf the payment portal fails, retain a screenshot or transaction reference and contact the accounts office. A next-working-day payment may be reviewed by the accounts office; it is not automatically guaranteed. Late fees or extensions require official confirmation.\n\n## Scholarship\nScholarship eligibility and disbursement depend on the approved scheme, submitted documents, and institutional verification. Contact the scholarship office for case-specific status.\n\n## Course Change\nStudents may submit a course-change request. Requests remain pending until reviewed by an authorized administrator. Approval depends on seat availability, eligibility, and academic rules.\n\n## Student Support\nStudents may raise a support ticket for technical, academic, or administrative assistance. Keep the ticket reference for follow-up. Duplicate open requests with the same description are reused.\n\n## Privacy and Security\nStudents may access only their own private records. Never share passwords, OTPs, PINs, or passcodes in chat.\n"""
MAX_TURNS = 3
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except Exception:
    pass

STUDENT_DATA_PATH = ROOT / "data" / "students_demo.csv"
DEMO_ADMIN = ("ADMIN01", "Programme Administrator", "admin")

def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def _hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return salt, digest

def init_db():
    with _connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            user_id TEXT PRIMARY KEY, full_name TEXT NOT NULL, role TEXT NOT NULL,
            password_salt TEXT NOT NULL, password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS students(
            student_id TEXT PRIMARY KEY REFERENCES users(user_id),
            programme TEXT NOT NULL, fee_status TEXT NOT NULL,
            scholarship_status TEXT NOT NULL, current_course TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS memories(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,
            memory_key TEXT NOT NULL, memory_value TEXT NOT NULL,
            updated_at TEXT NOT NULL, UNIQUE(user_id, memory_key)
        );
        CREATE TABLE IF NOT EXISTS tickets(
            ticket_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, category TEXT NOT NULL,
            description TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS change_requests(
            request_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, requested_course TEXT NOT NULL,
            status TEXT NOT NULL, requested_at TEXT NOT NULL, reviewed_by TEXT, reviewed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log(
            audit_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, actor_id TEXT NOT NULL,
            action TEXT NOT NULL, target_id TEXT, decision TEXT NOT NULL,
            approval_status TEXT, result TEXT NOT NULL, details TEXT
        );
        CREATE TABLE IF NOT EXISTS traces(
            run_id TEXT NOT NULL, timestamp TEXT NOT NULL, user_id TEXT NOT NULL,
            turn_no INTEGER NOT NULL, decision TEXT NOT NULL, tool_name TEXT,
            result_summary TEXT, latency_ms REAL, input_tokens INTEGER, output_tokens INTEGER,
            evidence_ids TEXT, status TEXT NOT NULL
        );
        """)
        demo_students = [
            ("STU1001", "Arjun Mehta", "AI Systems Engineering & Data Science", "₹25,000 pending", "Merit scholarship under review", "AI Systems Engineering"),
            ("STU1002", "Riya Shah", "Computer Science", "Paid in full", "Not currently enrolled", "Computer Science"),
            ("STU1003", "Kabir Patel", "Data Science", "₹10,000 pending", "Eligible - documents verified", "Data Science"),
        ]
        for sid, name, programme, fee, scholarship, course in demo_students:
            row = con.execute("SELECT 1 FROM users WHERE user_id=?", (sid,)).fetchone()
            if not row:
                salt, digest = _hash_password("demo123")
                con.execute("INSERT INTO users VALUES(?,?,?,?,?)", (sid, name, "student", salt, digest))
                con.execute("INSERT INTO students VALUES(?,?,?,?,?)", (sid, programme, fee, scholarship, course))
        row = con.execute("SELECT 1 FROM users WHERE user_id=?", (DEMO_ADMIN[0],)).fetchone()
        if not row:
            salt, digest = _hash_password("admin123")
            con.execute("INSERT INTO users VALUES(?,?,?,?,?)", (DEMO_ADMIN[0], DEMO_ADMIN[1], DEMO_ADMIN[2], salt, digest))

def authenticate(user_id, password):
    with _connect() as con:
        row = con.execute("SELECT * FROM users WHERE user_id=?", (user_id.strip().upper(),)).fetchone()
    if not row:
        return None
    _, digest = _hash_password(password, row["password_salt"])
    if secrets.compare_digest(digest, row["password_hash"]):
        return {"user_id": row["user_id"], "name": row["full_name"], "role": row["role"]}
    return None

def get_user(user_id):
    with _connect() as con:
        row = con.execute("SELECT user_id,full_name,role FROM users WHERE user_id=?", (user_id,)).fetchone()
    return dict(row) if row else None

def add_audit(actor_id, action, target_id, decision, approval_status, result, details=""):
    with _connect() as con:
        con.execute("INSERT INTO audit_log VALUES(?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(), actor_id, action,
             target_id, decision, approval_status, result, details[:500]))

def get_audit(limit=100):
    with _connect() as con:
        rows = con.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

def _authorized_student(requester_id, target_id=None):
    target = target_id or requester_id
    user = get_user(requester_id)
    if not user or user["role"] != "student":
        return False, "A signed-in student account is required."
    if target != requester_id:
        add_audit(requester_id, "private_record_access", target, "DENIED", "not_required",
                  "Blocked cross-student access", "Authorization enforced in tool code")
        return False, "Access denied: you can only view your own student record."
    return True, "allowed"

def get_fee_status(requester_id, target_id=None):
    ok, msg = _authorized_student(requester_id, target_id)
    if not ok: return {"ok": False, "error": msg}
    with _connect() as con:
        row = con.execute("SELECT fee_status FROM students WHERE student_id=?", (requester_id,)).fetchone()
    if not row: return {"ok": False, "error": "Student record not found."}
    add_audit(requester_id, "view_fee_status", requester_id, "ALLOWED", "not_required", "Fee status retrieved")
    return {"ok": True, "fee_status": row["fee_status"]}

def get_scholarship_status(requester_id, target_id=None):
    ok, msg = _authorized_student(requester_id, target_id)
    if not ok: return {"ok": False, "error": msg}
    with _connect() as con:
        row = con.execute("SELECT scholarship_status FROM students WHERE student_id=?", (requester_id,)).fetchone()
    if not row: return {"ok": False, "error": "Student record not found."}
    add_audit(requester_id, "view_scholarship_status", requester_id, "ALLOWED", "not_required", "Scholarship status retrieved")
    return {"ok": True, "scholarship_status": row["scholarship_status"]}

def get_student_record(requester_id, target_id=None):
    ok, msg = _authorized_student(requester_id, target_id)
    if not ok: return {"ok": False, "error": msg}
    with _connect() as con:
        row = con.execute("SELECT student_id,programme,fee_status,scholarship_status,current_course FROM students WHERE student_id=?",
                          (requester_id,)).fetchone()
    if not row: return {"ok": False, "error": "Student record not found."}
    add_audit(requester_id, "view_student_record", requester_id, "ALLOWED", "not_required", "Own record retrieved")
    return {"ok": True, **dict(row)}

def _policy_chunks():
    text = POLICY_TEXT
    chunks = []
    for block in re.split(r"\n(?=## )", text):
        block = block.strip()
        if block and block.startswith("## "):
            title = block.splitlines()[0].replace("## ", "").strip()
            cid = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
            chunks.append((cid, title, block))
    return chunks

def search_policy(query, top_k=2):
    terms = set(re.findall(r"[a-z0-9₹]+", query.lower()))
    scored = []
    for cid, title, body in _policy_chunks():
        words = set(re.findall(r"[a-z0-9₹]+", (title + " " + body).lower()))
        score = len(terms & words)
        if score:
            scored.append((score, cid, title, body))
    scored.sort(reverse=True)
    if not scored:
        return {"ok": True, "found": False, "evidence": [], "message": "The sample handbook does not contain enough information to answer this question."}
    return {"ok": True, "found": True,
            "evidence": [{"chunk_id": c, "title": t, "text": b} for _,c,t,b in scored[:top_k]]}

SENSITIVE_PATTERNS = [
    r"\botp\b", r"\bpassword\b", r"\bpasscode\b", r"\bpin\b",
    r"\b\d{4,8}\b"
]
def contains_sensitive(text):
    low = text.lower()
    return any(re.search(p, low) for p in SENSITIVE_PATTERNS)

def save_safe_memory(user_id, text):
    """Only allow a small whitelist of useful, non-sensitive preferences."""
    if contains_sensitive(text):
        return {"ok": False, "saved": False, "message": "This looks like temporary or sensitive information, so it was not saved."}
    patterns = [
        (r"(?:remember|save)\s+(?:that\s+)?my preferred name is\s+([A-Za-z][A-Za-z '-]{0,30})", "preferred_name"),
        (r"(?:remember|save)\s+(?:that\s+)?my communication preference is\s+(email|phone|whatsapp)", "communication_preference"),
        (r"(?:remember|save)\s+(?:that\s+)?my programme is\s+([A-Za-z0-9 &/-]{3,60})", "programme")
    ]
    for pattern, key in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            value = match.group(1).strip().rstrip(".")
            with _connect() as con:
                con.execute("""INSERT INTO memories(user_id,memory_key,memory_value,updated_at)
                    VALUES(?,?,?,?) ON CONFLICT(user_id,memory_key) DO UPDATE SET
                    memory_value=excluded.memory_value, updated_at=excluded.updated_at""",
                    (user_id, key, value, datetime.now(timezone.utc).isoformat()))
            add_audit(user_id, "save_memory", user_id, "ALLOWED", "not_required", "Safe preference saved", key)
            return {"ok": True, "saved": True, "memory_key": key, "memory_value": value}
    return {"ok": False, "saved": False, "message": "I can save only a preferred name, programme, or communication preference. Please use: 'Remember my preferred name is ...'."}

def get_memory(user_id, query=""):
    with _connect() as con:
        rows = con.execute("SELECT memory_key,memory_value FROM memories WHERE user_id=? ORDER BY updated_at DESC",
                           (user_id,)).fetchall()
    if not rows:
        return {"ok": True, "found": False, "items": []}
    q = query.lower()
    selected = [dict(r) for r in rows if not q or any(w in (r["memory_key"]+" "+r["memory_value"]).lower() for w in q.split())]
    if not selected: selected = [dict(r) for r in rows]
    return {"ok": True, "found": True, "items": selected[:4]}

def create_support_request(user_id, description):
    # Idempotency: one open ticket with the same description is reused.
    with _connect() as con:
        existing = con.execute("SELECT ticket_id,status FROM tickets WHERE user_id=? AND description=? AND status='Open'",
                               (user_id, description[:300])).fetchone()
        if existing:
            return {"ok": True, "ticket_id": existing["ticket_id"], "status": existing["status"], "reused": True}
        ticket_id = "TKT-" + uuid.uuid4().hex[:8].upper()
        con.execute("INSERT INTO tickets VALUES(?,?,?,?,?,?)",
                    (ticket_id, user_id, "General support", description[:300], "Open", datetime.now(timezone.utc).isoformat()))
    add_audit(user_id, "create_support_request", user_id, "ALLOWED", "not_required", "Support request created", ticket_id)
    return {"ok": True, "ticket_id": ticket_id, "status": "Open", "reused": False}

def request_course_change(user_id, requested_course):
    ok, msg = _authorized_student(user_id, user_id)
    if not ok: return {"ok": False, "error": msg}
    request_id = "CR-" + uuid.uuid4().hex[:8].upper()
    with _connect() as con:
        con.execute("INSERT INTO change_requests VALUES(?,?,?,?,?,?,?)",
                    (request_id, user_id, requested_course[:100], "Pending approval",
                     datetime.now(timezone.utc).isoformat(), None, None))
    add_audit(user_id, "course_change_request", user_id, "ALLOWED", "PENDING", "Awaiting administrator approval", request_id)
    return {"ok": True, "request_id": request_id, "status": "Pending approval",
            "message": "Your request has been recorded. The course will not change unless an administrator approves it."}

def list_pending_changes():
    with _connect() as con:
        rows = con.execute("""SELECT c.request_id,c.user_id,u.full_name,c.requested_course,c.status,c.requested_at
            FROM change_requests c JOIN users u ON u.user_id=c.user_id
            WHERE c.status='Pending approval' ORDER BY c.requested_at""").fetchall()
    return [dict(r) for r in rows]

def review_course_change(admin_id, request_id, approve):
    admin = get_user(admin_id)
    if not admin or admin["role"] != "admin":
        add_audit(admin_id, "review_course_change", request_id, "DENIED", "not_authorized", "Only an administrator can review")
        return {"ok": False, "error": "Administrator permission is required."}
    with _connect() as con:
        req = con.execute("SELECT * FROM change_requests WHERE request_id=?", (request_id,)).fetchone()
        if not req: return {"ok": False, "error": "Request not found."}
        if req["status"] != "Pending approval":
            return {"ok": False, "error": "This request has already been reviewed."}
        status = "Approved" if approve else "Rejected"
        con.execute("UPDATE change_requests SET status=?,reviewed_by=?,reviewed_at=? WHERE request_id=?",
                    (status, admin_id, datetime.now(timezone.utc).isoformat(), request_id))
        if approve:
            con.execute("UPDATE students SET current_course=? WHERE student_id=?",
                        (req["requested_course"], req["user_id"]))
    add_audit(admin_id, "review_course_change", req["user_id"], "ALLOWED", status.upper(),
              "Course updated" if approve else "Course change not executed", request_id)
    return {"ok": True, "status": status, "executed": bool(approve)}

def get_change_requests(user_id):
    with _connect() as con:
        rows = con.execute("SELECT request_id,requested_course,status,requested_at FROM change_requests WHERE user_id=? ORDER BY requested_at DESC",
                           (user_id,)).fetchall()
    return [dict(r) for r in rows]

def log_trace(run_id, user_id, turn_no, decision, tool_name, summary, latency_ms,
              evidence_ids=None, status="ok", input_tokens=None, output_tokens=None):
    with _connect() as con:
        con.execute("INSERT INTO traces VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, datetime.now(timezone.utc).isoformat(), user_id, turn_no, decision, tool_name,
             summary[:300], latency_ms, input_tokens, output_tokens,
             json.dumps(evidence_ids or []), status))

def get_recent_traces(limit=100):
    with _connect() as con:
        rows = con.execute("SELECT * FROM traces ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

def detect_target_id(text):
    m = re.search(r"\b(STU\d{4})\b", text.upper())
    return m.group(1) if m else None

def deterministic_plan(text):
    t = text.lower()
    target = detect_target_id(text)

    # ── 1. Memory write (highest priority – explicit save intent) ─────────────
    if re.search(r"\b(remember|save)\b", t) and re.search(r"\b(my preferred name|my programme|my communication preference)\b", t):
        return "save_memory", {"text": text}

    # ── 2. Memory read ────────────────────────────────────────────────────────
    if "what do you remember" in t or "my preference" in t or "my preferred name" in t or "what is my programme" in t:
        return "get_memory", {"query": text}

    # ── 3. Policy questions (check BEFORE fee/scholarship to avoid keyword clash) ──
    # Trigger when the user explicitly asks about policy, rules, or handbook topics.
    POLICY_SIGNALS = [
        "policy", "what does the policy", "handbook", "rule",
        "next working day", "payment portal", "late fee", "late payment",
        "installment", "refund", "deadline", "course change rule",
        "what happens if", "can i pay", "is it allowed", "am i eligible",
    ]
    if any(x in t for x in POLICY_SIGNALS):
        return "search_policy", {"query": text}

    # ── 4. Personal fee status (only when asking about OWN fee record) ────────
    # "fee payment" removed here — it is ambiguous and caught by policy above.
    if any(x in t for x in ["fee status", "fees status", "fee balance", "my fees", "my fee", "how much do i owe"]):
        return "get_fee_status", {"target_id": target}

    # ── 5. Scholarship status ─────────────────────────────────────────────────
    if any(x in t for x in ["scholarship status", "my scholarship", "scholarship"]):
        return "get_scholarship_status", {"target_id": target}

    # ── 6. Course-change request ──────────────────────────────────────────────
    if any(x in t for x in ["course change", "change my course", "switch my course", "transfer programme"]):
        m = re.search(r"(?:to|into)\s+(.+?)(?:[?.!]|$)", text, re.I)
        course = m.group(1).strip() if m else "Requested programme (please confirm exact name)"
        return "request_course_change", {"requested_course": course}

    # ── 7. Support ticket ─────────────────────────────────────────────────────
    if any(x in t for x in ["support request", "raise a ticket", "create a ticket", "need help", "complaint"]):
        return "create_support_request", {"description": text}

    return None, {}

def _dispatch(tool_name, args, user):
    uid = user["user_id"]
    if tool_name == "get_fee_status": return get_fee_status(uid, args.get("target_id"))
    if tool_name == "get_scholarship_status": return get_scholarship_status(uid, args.get("target_id"))
    if tool_name == "get_student_record": return get_student_record(uid, args.get("target_id"))
    if tool_name == "search_policy": return search_policy(args.get("query", ""))
    if tool_name == "get_memory": return get_memory(uid, args.get("query", ""))
    if tool_name == "save_memory": return save_safe_memory(uid, args.get("text", ""))
    if tool_name == "create_support_request": return create_support_request(uid, args.get("description", ""))
    if tool_name == "request_course_change": return request_course_change(uid, args.get("requested_course", ""))
    return {"ok": False, "error": "Tool not allowed."}

def _format_result(tool_name, result):
    if not result.get("ok"):
        return result.get("error") or result.get("message", "The request could not be completed.")
    if tool_name == "get_fee_status":
        return "Your fee status is: " + result["fee_status"]
    if tool_name == "get_scholarship_status":
        return "Your scholarship status is: " + result["scholarship_status"]
    if tool_name == "search_policy":
        if not result.get("found"): return result["message"]
        return "\n\n".join(x["text"] for x in result["evidence"])
    if tool_name == "get_memory":
        if not result.get("found"): return "I do not have a saved preference for you yet."
        return "Saved information: " + "; ".join(f'{x["memory_key"].replace("_"," ")} = {x["memory_value"]}' for x in result["items"])
    if tool_name == "save_memory":
        return ("I saved this non-sensitive preference: " + result["memory_key"].replace("_"," ") + " = " + result["memory_value"]) if result.get("saved") else result["message"]
    if tool_name == "create_support_request":
        return f'Your support request is {result["ticket_id"]} and its status is {result["status"]}.'
    if tool_name == "request_course_change":
        return f'Your request {result["request_id"]} is {result["status"]}. {result["message"]}'
    return str(result)


TOOL_SCHEMAS = [
    {"type":"function","function":{"name":"get_fee_status","description":"Get the signed-in student's own fee status. Never use this to inspect another student.","parameters":{"type":"object","properties":{"target_id":{"type":"string","description":"Optional student ID mentioned by the user; the application will deny cross-student access."}},"required":[]}}},
    {"type":"function","function":{"name":"get_scholarship_status","description":"Get the signed-in student's own scholarship status.","parameters":{"type":"object","properties":{"target_id":{"type":"string"}},"required":[]}}},
    {"type":"function","function":{"name":"search_policy","description":"Retrieve only relevant sections from the demonstration student handbook. Use for payment, scholarship, course-change and support policy questions.","parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}},
    {"type":"function","function":{"name":"get_memory","description":"Retrieve safe saved preferences for the signed-in student.","parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}},
    {"type":"function","function":{"name":"save_memory","description":"Save only a whitelisted non-sensitive preference such as preferred name, programme or communication preference. Never save credentials or temporary secrets.","parameters":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}},
    {"type":"function","function":{"name":"create_support_request","description":"Create a support request for the signed-in student and return a reference number.","parameters":{"type":"object","properties":{"description":{"type":"string"}},"required":["description"]}}},
    {"type":"function","function":{"name":"request_course_change","description":"Submit a course-change request. It must remain pending until an administrator approves it.","parameters":{"type":"object","properties":{"requested_course":{"type":"string"}},"required":["requested_course"]}}}
]

def run_agent_with_groq(user, text):
    """Optional LLM tool-calling loop. The app validates every tool request before dispatch."""
    from groq import Groq
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    uid = user["user_id"]
    run_id = str(uuid.uuid4())
    start = time.perf_counter()
    messages = [
        {"role":"system","content":(
            "You are a student support assistant. Use the available tools when current private records, "
            "policy evidence, saved preferences or actions are needed. The application enforces permissions. "
            "Never claim a write action succeeded without a successful tool result. Course changes require "
            "administrator approval. If policy evidence is missing, say so. Do not ask for or store passwords, "
            "OTPs or PINs. Use only the current question and tool results; do not invent institutional rules."
        )},
        {"role":"user","content":text}
    ]
    tools_used, evidence = [], []
    input_tokens = output_tokens = 0
    for turn in range(1, MAX_TURNS + 1):
        response = client.chat.completions.create(
            model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            messages=messages, tools=TOOL_SCHEMAS, tool_choice="auto",
            temperature=0, max_tokens=700
        )
        choice = response.choices[0]
        usage = getattr(response, "usage", None)
        if usage:
            input_tokens += getattr(usage, "prompt_tokens", 0) or 0
            output_tokens += getattr(usage, "completion_tokens", 0) or 0
        message = choice.message
        if not message.tool_calls:
            answer = message.content or "I could not produce a final response from the available evidence."
            total = (time.perf_counter()-start)*1000
            log_trace(run_id, uid, turn, "final_answer", None, "LLM final response",
                      total, evidence, input_tokens=input_tokens, output_tokens=output_tokens)
            return {"answer":answer,"run_id":run_id,"tools":tools_used,"evidence":evidence,
                    "latency_ms":total,"tokens":{"input":input_tokens,"output":output_tokens}}
        # Preserve the assistant tool-call message in the model conversation.
        messages.append({"role":"assistant","content":message.content or "",
                         "tool_calls":[tc.model_dump(exclude_none=True) for tc in message.tool_calls]})
        for call in message.tool_calls:
            name = call.function.name
            try:
                args = json.loads(call.function.arguments or "{}")
                if not isinstance(args, dict): raise ValueError("Tool arguments must be an object.")
                if name not in {x["function"]["name"] for x in TOOL_SCHEMAS}:
                    result = {"ok":False,"error":"Tool not allowed."}
                elif name in ("search_policy","get_memory") and not str(args.get("query","")).strip():
                    result = {"ok":False,"error":"A query is required."}
                elif name == "request_course_change" and not str(args.get("requested_course","")).strip():
                    result = {"ok":False,"error":"Requested course is required."}
                elif name == "create_support_request" and not str(args.get("description","")).strip():
                    result = {"ok":False,"error":"A request description is required."}
                else:
                    result = _dispatch(name, args, user)
                tools_used.append(name)
                if name == "search_policy" and result.get("found"):
                    evidence.extend(x["chunk_id"] for x in result["evidence"])
                if name == "get_memory" and result.get("found"):
                    evidence.extend("memory:"+x["memory_key"] for x in result["items"])
                summary = "tool result returned; private values omitted"
                status = "ok" if result.get("ok") else "blocked_or_error"
                log_trace(run_id, uid, turn, "tool_request_and_observation", name, summary,
                          (time.perf_counter()-start)*1000, evidence, status=status,
                          input_tokens=input_tokens, output_tokens=output_tokens)
                messages.append({"role":"tool","tool_call_id":call.id,"content":json.dumps(result, ensure_ascii=False)})
            except Exception as exc:
                messages.append({"role":"tool","tool_call_id":call.id,
                                 "content":json.dumps({"ok":False,"error":"Tool request could not be processed."})})
                log_trace(run_id, uid, turn, "tool_validation_error", name,
                          "Invalid tool arguments or tool error", (time.perf_counter()-start)*1000,
                          evidence, status="error", input_tokens=input_tokens, output_tokens=output_tokens)
    total = (time.perf_counter()-start)*1000
    return {"answer":"I reached the maximum number of tool turns. Please narrow your question or contact the relevant office.",
            "run_id":run_id,"tools":tools_used,"evidence":evidence,"latency_ms":total,
            "tokens":{"input":input_tokens,"output":output_tokens}}

def run_agent(user, text, use_llm=False):
    """Manual bounded agent loop. Uses optional Groq tool selection; safe deterministic fallback."""
    mentioned_id = detect_target_id(text)
    if mentioned_id and mentioned_id != user["user_id"] and any(
        word in text.lower() for word in ["fee", "scholarship", "record", "student"]
    ):
        run_id = str(uuid.uuid4())
        started = time.perf_counter()
        denied = get_fee_status(user["user_id"], mentioned_id)
        total = (time.perf_counter()-started)*1000
        log_trace(run_id, user["user_id"], 1, "authorization_denied", "private_record_tool",
                  "Cross-student request blocked; no private data returned", total, status="blocked")
        return {"answer":denied.get("error","Access denied."),"run_id":run_id,"tools":["private_record_tool"],
                "evidence":[],"latency_ms":total,"tokens":None}
    if use_llm and os.getenv("GROQ_API_KEY"):
        try:
            if contains_sensitive(text) and any(x in text.lower() for x in ["otp", "password", "passcode", "pin"]):
                # Sensitive content is not sent to the provider or persisted.
                pass
            else:
                return run_agent_with_groq(user, text)
        except Exception:
            # Provider errors fall back to the deterministic planner and are not presented as success.
            pass
    run_id = str(uuid.uuid4())
    start = time.perf_counter()
    if contains_sensitive(text) and any(x in text.lower() for x in ["otp", "password", "passcode", "pin"]):
        # Never store raw chat or credentials in memory/traces.
        answer = "Please do not share passwords, OTPs or PINs in chat. I will not save this information in persistent memory."
        log_trace(run_id, user["user_id"], 0, "sensitive_input_blocked", None,
                  "Sensitive input detected; content not stored", (time.perf_counter()-start)*1000, status="blocked")
        return {"answer": answer, "run_id": run_id, "tools": [], "evidence": [], "latency_ms": (time.perf_counter()-start)*1000, "tokens": None}
    tool_name, args = deterministic_plan(text)
    if tool_name is None:
        answer = "I can help with fee status, scholarship status, payment and student policies, saved preferences, support requests or course-change requests. Please tell me which one you need."
        log_trace(run_id, user["user_id"], 0, "direct_response", None, "Help message; no tool required",
                  (time.perf_counter()-start)*1000)
        return {"answer": answer, "run_id": run_id, "tools": [], "evidence": [], "latency_ms": (time.perf_counter()-start)*1000, "tokens": None}

    tools_used, evidence = [], []
    for turn in range(1, MAX_TURNS + 1):
        t0 = time.perf_counter()
        try:
            result = _dispatch(tool_name, args, user)
        except Exception:
            result = {"ok": False, "error": "The requested tool is temporarily unavailable. Please try again later."}
        elapsed = (time.perf_counter()-t0)*1000
        tools_used.append(tool_name)
        if tool_name == "search_policy" and result.get("found"):
            evidence = [x["chunk_id"] for x in result["evidence"]]
        if tool_name == "get_memory" and result.get("found"):
            evidence = ["memory:" + x["memory_key"] for x in result["items"]]
        status = "ok" if result.get("ok") else "blocked_or_error"
        summary = ("policy chunks retrieved" if tool_name == "search_policy" and result.get("found")
                   else "memory items retrieved" if tool_name == "get_memory" and result.get("found")
                   else "result recorded; private values omitted")
        log_trace(run_id, user["user_id"], turn, "tool_request_and_observation", tool_name,
                  summary, elapsed, evidence, status=status)
        answer = _format_result(tool_name, result)
        break
    total = (time.perf_counter()-start)*1000
    return {"answer": answer, "run_id": run_id, "tools": tools_used, "evidence": evidence,
            "latency_ms": total, "tokens": None}

def init():
    init_db()


# --------------------------- Streamlit interface ---------------------------
def _force_close_eval_db(db_path):
    """Force-close any lingering SQLite connections to the eval DB on Windows."""
    try:
        import sqlite3 as _sq
        con = _sq.connect(str(db_path))
        con.close()
    except Exception:
        pass
    # Give the OS a moment to release the file handle
    time.sleep(0.15)

def run_evaluation():
    """Run deterministic assignment checks against an isolated temporary database."""
    import tempfile, shutil
    global DB_PATH
    original = DB_PATH
    results = []
    # Create temp dir manually so we control cleanup timing
    td_obj = tempfile.mkdtemp()
    td = Path(td_obj)
    try:
        DB_PATH = td / "evaluation.sqlite"
        init_db()

        def check(name, fn):
            try:
                passed, note = fn()
            except Exception as exc:
                passed, note = False, type(exc).__name__ + ": " + str(exc)
            results.append({"Test": name, "Passed": bool(passed), "Observation": note})

        s = authenticate("STU1001", "demo123")
        a = authenticate("ADMIN01", "admin123")
        check("Student authentication",        lambda: (bool(s), "Demo student can sign in"))
        check("Administrator authentication",  lambda: (bool(a), "Admin can sign in"))
        check("Own fee status",                lambda: (get_fee_status("STU1001").get("ok"), "Own private fee record available"))
        check("Own scholarship status",        lambda: (get_scholarship_status("STU1001").get("ok"), "Own scholarship record available"))
        pol = search_policy("payment portal failed next working day")
        check("Selective policy retrieval",    lambda: (pol.get("found") and any("fee-payment" in x["chunk_id"] for x in pol["evidence"]), "Relevant fee policy retrieved"))
        mem = save_safe_memory("STU1001", "Remember my preferred name is Sid")
        check("Persistent safe memory",        lambda: (mem.get("saved") and get_memory("STU1001").get("found"), "Whitelisted preference stored"))
        secret = save_safe_memory("STU1001", "Remember my password is abc123")
        check("Sensitive memory blocked",      lambda: (not secret.get("saved"), "Credential-like content rejected"))
        ticket = create_support_request("STU1001", "Payment portal issue")
        check("Support ticket creation",       lambda: (ticket.get("ok") and ticket.get("ticket_id","").startswith("TKT-"), "Ticket reference returned"))
        agent = run_agent(s, "What is my current fee status?")
        check("Agent selects fee tool",        lambda: ("get_fee_status" in agent["tools"] and "fee status" in agent["answer"].lower(), "Tool dispatched and result formatted"))
        agent2 = run_agent(s, "The payment portal failed. Can I pay on the next working day?")
        check("Agent retrieves policy",        lambda: ("does not guarantee" in agent2["answer"].lower() or "not automatically guaranteed" in agent2["answer"].lower(), "No unsupported promise made"))
        sensitive = run_agent(s, "My OTP is 123456")
        check("Sensitive chat blocked",        lambda: ("will not save" in sensitive["answer"].lower(), "Sensitive input not persisted"))
        denied = run_agent(s, "Show fee status for STU1002")
        check("Cross-student access blocked",  lambda: ("access denied" in denied["answer"].lower(), "Signed-in identity enforced"))
        change = request_course_change("STU1001", "PGDM Big Data Analytics")
        before = get_student_record("STU1001")["current_course"]
        reject = review_course_change("ADMIN01", change["request_id"], False)
        after  = get_student_record("STU1001")["current_course"]
        check("Rejected approval does not execute", lambda: (reject.get("status") == "Rejected" and before == after, "Course unchanged after rejection"))
        change2 = request_course_change("STU1001", "PGDM Big Data Analytics")
        approve = review_course_change("ADMIN01", change2["request_id"], True)
        updated = get_student_record("STU1001")["current_course"]
        check("Approved action executes",      lambda: (approve.get("executed") and updated == "PGDM Big Data Analytics", "Approved course change executed"))
        unknown = search_policy("guaranteed fee waiver tomorrow")
        check("Unsupported policy not invented", lambda: (not unknown.get("found") or "not automatically guaranteed" in " ".join(x["text"] for x in unknown["evidence"]).lower(), "No affirmative guarantee fabricated"))
        audit = get_audit()
        check("Audit evidence",                lambda: (len(audit) >= 6 and any(x["decision"] == "DENIED" for x in audit), "Allowed and denied actions audited"))
    finally:
        DB_PATH = original
        # Explicitly close lingering connections before deleting the temp dir
        _force_close_eval_db(td / "evaluation.sqlite")
        try:
            shutil.rmtree(td_obj, ignore_errors=True)
        except Exception:
            pass   # Non-fatal on Windows; temp dir will be cleaned at OS level
    return results

def _friendly_action(action):
    return {
        "view_fee_status":        "Viewed Fee Status",
        "view_scholarship_status":"Viewed Scholarship Status",
        "view_student_record":    "Viewed Student Record",
        "save_memory":            "Saved Preference",
        "create_support_request": "Created Support Ticket",
        "course_change_request":  "Submitted Course-Change Request",
        "review_course_change":   "Reviewed Course-Change Request",
        "private_record_access":  "Attempted Cross-Student Access",
    }.get(action, action.replace("_", " ").title())

def _friendly_decision(decision):
    return {"ALLOWED": "✅ Allowed", "DENIED": "🚫 Denied"}.get(decision.upper(), decision)

def _friendly_approval(status):
    if not status or status in ("not_required",): return "—"
    return {"PENDING": "⏳ Pending", "APPROVED": "✅ Approved", "REJECTED": "❌ Rejected",
            "not_authorized": "🔒 Not Authorized"}.get(status.upper(), status.title())

def _fmt_ts(ts):
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(ts).astimezone()
        return dt.strftime("%d %b %Y, %I:%M %p")
    except Exception:
        return ts or "—"

def _status_badge(status):
    colours = {"Pending approval": "#f59e0b", "Approved": "#10b981", "Rejected": "#ef4444", "Open": "#3b82f6", "Closed": "#6b7280"}
    c = colours.get(status, "#6b7280")
    return f'<span style="background:{c};color:#fff;padding:2px 10px;border-radius:12px;font-size:0.78rem;font-weight:600">{status}</span>'

def main():
    import streamlit as st
    import pandas as pd

    st.set_page_config(
        page_title="Student Support Portal",
        page_icon="🎓",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init()

    # ── Global CSS ─────────────────────────────────────────────────────────────
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

    /* Page background */
    .stApp { background: #f0f4f8; }

    /* Top header bar */
    .portal-header {
        background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
        padding: 1.6rem 2rem 1.4rem 2rem;
        border-radius: 14px;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 20px rgba(37,99,235,0.25);
    }
    .portal-header h1 { color: #fff; font-size: 1.75rem; font-weight: 700; margin: 0; letter-spacing: -0.5px; }
    .portal-header p  { color: #bfdbfe; font-size: 0.85rem; margin: 4px 0 0 0; }

    /* Card */
    .card {
        background: #ffffff;
        border-radius: 12px;
        padding: 1.3rem 1.5rem;
        box-shadow: 0 1px 6px rgba(0,0,0,0.07);
        margin-bottom: 1rem;
        border: 1px solid #e2e8f0;
    }
    .card-title { font-size: 0.72rem; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 4px; }
    .card-value { font-size: 1.5rem; font-weight: 700; color: #1e293b; }
    .card-sub   { font-size: 0.78rem; color: #94a3b8; margin-top: 2px; }

    /* Record info rows */
    .info-row { display:flex; align-items:center; padding: 9px 0; border-bottom: 1px solid #f1f5f9; }
    .info-row:last-child { border-bottom: none; }
    .info-label { font-size: 0.8rem; color: #64748b; font-weight: 500; width: 160px; flex-shrink: 0; }
    .info-value { font-size: 0.9rem; color: #1e293b; font-weight: 500; }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: #1e293b !important;
    }
    section[data-testid="stSidebar"] * { color: #e2e8f0 !important; }
    section[data-testid="stSidebar"] .stTextInput input {
        background: #334155 !important;
        border: 1px solid #475569 !important;
        color: #f8fafc !important;
        border-radius: 8px !important;
    }
    section[data-testid="stSidebar"] .stButton button {
        background: #2563eb !important;
        color: #fff !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        border: none !important;
    }

    /* Chat bubbles */
    .stChatMessage { border-radius: 12px !important; }

    /* Buttons */
    .stButton > button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        transition: all 0.15s ease !important;
    }
    .stButton > button:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(37,99,235,0.2) !important; }

    /* Expander */
    details { border-radius: 10px !important; border: 1px solid #e2e8f0 !important; background: #fff !important; }

    /* Metric overrides */
    [data-testid="stMetric"] {
        background: #fff;
        border-radius: 12px;
        padding: 1rem 1.2rem;
        border: 1px solid #e2e8f0;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05);
    }
    [data-testid="stMetricLabel"] { font-size: 0.75rem !important; color: #64748b !important; font-weight: 600 !important; text-transform: uppercase !important; letter-spacing: 0.05em !important; }
    [data-testid="stMetricValue"] { font-size: 1.4rem !important; font-weight: 700 !important; color: #1e293b !important; }

    /* DataFrame */
    [data-testid="stDataFrame"] { border-radius: 10px; overflow: hidden; border: 1px solid #e2e8f0; }

    /* Section headings */
    .section-heading {
        font-size: 1.05rem;
        font-weight: 700;
        color: #1e293b;
        margin: 1.4rem 0 0.7rem 0;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .section-heading::after {
        content: '';
        flex: 1;
        height: 1px;
        background: #e2e8f0;
        margin-left: 8px;
    }

    /* Approval card */
    .approval-card {
        background: #fff;
        border: 1px solid #e2e8f0;
        border-left: 4px solid #f59e0b;
        border-radius: 10px;
        padding: 1rem 1.3rem;
        margin-bottom: 0.8rem;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05);
    }
    .approval-card .req-id { font-size: 0.75rem; color: #94a3b8; font-weight: 600; text-transform: uppercase; }
    .approval-card .req-name { font-size: 1rem; font-weight: 700; color: #1e293b; margin: 2px 0; }
    .approval-card .req-course { font-size: 0.88rem; color: #475569; }

    /* Landing page hero */
    .hero-card {
        background: linear-gradient(135deg, #1e3a5f 0%, #1d4ed8 100%);
        border-radius: 16px;
        padding: 2.5rem 2rem;
        color: #fff;
        text-align: center;
        box-shadow: 0 8px 30px rgba(37,99,235,0.3);
        margin-bottom: 1.5rem;
    }
    .hero-card h2 { font-size: 1.8rem; font-weight: 700; margin: 0 0 8px 0; }
    .hero-card p  { color: #bfdbfe; font-size: 0.95rem; margin: 0; }

    /* Feature pill */
    .feature-pill {
        display: inline-block;
        background: #eff6ff;
        color: #1d4ed8;
        border: 1px solid #bfdbfe;
        border-radius: 20px;
        padding: 4px 14px;
        font-size: 0.78rem;
        font-weight: 600;
        margin: 3px;
    }

    /* Audit table row colours handled via pandas styler */
    </style>
    """, unsafe_allow_html=True)

    # ── Session state ──────────────────────────────────────────────────────────
    if "user" not in st.session_state: st.session_state.user = None
    if "chat" not in st.session_state: st.session_state.chat = []

    # ── Sidebar ────────────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("### 🎓 Student Portal")
        st.markdown("---")
        if not st.session_state.user:
            st.markdown("**Sign In to Your Account**")
            uid = st.text_input("User ID", placeholder="e.g. STU1001 or ADMIN01", label_visibility="collapsed")
            pwd = st.text_input("Password", type="password", placeholder="Password", label_visibility="collapsed")
            if st.button("🔐  Sign In", type="primary", use_container_width=True):
                account = authenticate(uid, pwd)
                if account:
                    st.session_state.user = account
                    st.session_state.chat = []
                    st.rerun()
                else:
                    st.error("Invalid ID or password. Please try again.")
            st.markdown("---")
            st.markdown("**Demo Credentials**")
            st.markdown("""
            | ID | Role | Password |
            |---|---|---|
            | STU1001 | Student | demo123 |
            | STU1002 | Student | demo123 |
            | STU1003 | Student | demo123 |
            | ADMIN01 | Admin | admin123 |
            """)
        else:
            u = st.session_state.user
            role_icon = "🛡️" if u["role"] == "admin" else "🎓"
            st.markdown(f"""
            <div style="background:#334155;border-radius:10px;padding:12px 14px;margin-bottom:12px">
              <div style="font-size:0.75rem;color:#94a3b8;font-weight:600;text-transform:uppercase">Signed In As</div>
              <div style="font-size:1rem;font-weight:700;color:#f8fafc;margin-top:2px">{role_icon} {u['name']}</div>
              <div style="font-size:0.78rem;color:#93c5fd;margin-top:2px">{u['role'].title()} · {u['user_id']}</div>
            </div>
            """, unsafe_allow_html=True)
            if st.button("↩  Sign Out", use_container_width=True):
                st.session_state.user = None
                st.session_state.chat = []
                st.rerun()
            st.markdown("---")
            if u["role"] == "student":
                st.markdown("**Quick Actions**")
                st.markdown("""
                - 💰 Ask about your fees
                - 🏅 Check scholarship status
                - 📋 Raise a support ticket
                - 🔄 Request a course change
                - 💾 Save preferences
                - 📜 Query policy handbook
                """)
        st.markdown("---")
        st.markdown('<div style="font-size:0.72rem;color:#64748b;text-align:center">Demo portal · Not an official system</div>', unsafe_allow_html=True)

    # ── Not signed in – landing page ───────────────────────────────────────────
    if not st.session_state.user:
        st.markdown("""
        <div class="hero-card">
          <div style="font-size:3rem;margin-bottom:10px">🎓</div>
          <h2>Intelligent Student Support Portal</h2>
          <p>Your AI-powered academic support assistant — fees, scholarships, policies & more</p>
        </div>
        """, unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("""
            <div class="card">
              <div class="card-title">👨‍🎓 For Students</div>
              <div style="margin-top:10px">
                <span class="feature-pill">💰 Fee Status</span>
                <span class="feature-pill">🏅 Scholarships</span>
                <span class="feature-pill">📋 Support Tickets</span>
                <span class="feature-pill">🔄 Course Change</span>
                <span class="feature-pill">💾 Preferences</span>
                <span class="feature-pill">📜 Policy Lookup</span>
              </div>
            </div>
            """, unsafe_allow_html=True)
        with c2:
            st.markdown("""
            <div class="card">
              <div class="card-title">🛡️ For Administrators</div>
              <div style="margin-top:10px">
                <span class="feature-pill">✅ Approve Requests</span>
                <span class="feature-pill">❌ Reject Requests</span>
                <span class="feature-pill">📊 Audit Log</span>
                <span class="feature-pill">🧪 Run Evaluations</span>
              </div>
            </div>
            """, unsafe_allow_html=True)
        st.info("👈  Use the sidebar to sign in with a demo account.")
        return

    user = st.session_state.user

    # ── Page header ────────────────────────────────────────────────────────────
    role_label = "Administrator Dashboard" if user["role"] == "admin" else "Student Dashboard"
    st.markdown(f"""
    <div class="portal-header">
      <h1>🎓 Student Support Portal</h1>
      <p>{role_label} &nbsp;·&nbsp; Agentic AI Engineering &nbsp;·&nbsp; Offline-first academic demonstration</p>
    </div>
    """, unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════════════════
    # ADMIN VIEW
    # ══════════════════════════════════════════════════════════════════════════
    if user["role"] == "admin":

        # ── Metrics row ───────────────────────────────────────────────────────
        pending = list_pending_changes()
        audits  = get_audit()
        denied  = sum(1 for a in audits if a.get("decision","").upper() == "DENIED")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("⏳ Pending Requests", len(pending))
        m2.metric("📋 Total Audit Events", len(audits))
        m3.metric("🚫 Blocked Actions", denied)
        m4.metric("✅ Permitted Actions", len(audits) - denied)

        # ── Pending approvals ─────────────────────────────────────────────────
        st.markdown('<div class="section-heading">⏳ Pending Course-Change Requests</div>', unsafe_allow_html=True)
        if not pending:
            st.success("✅ No pending requests — all caught up!")
        else:
            for req in pending:
                st.markdown(f"""
                <div class="approval-card">
                  <div class="req-id">{req['request_id']} &nbsp;·&nbsp; Submitted {_fmt_ts(req['requested_at'])}</div>
                  <div class="req-name">{req['full_name']} &nbsp;<span style="color:#94a3b8;font-weight:400;font-size:0.82rem">({req['user_id']})</span></div>
                  <div class="req-course">Requested Course: <strong>{req['requested_course']}</strong></div>
                </div>
                """, unsafe_allow_html=True)
                c1, c2, c3 = st.columns([2, 2, 6])
                if c1.button("✅ Approve", key="ap_"+req["request_id"], type="primary", use_container_width=True):
                    out = review_course_change(user["user_id"], req["request_id"], True)
                    st.success(f"✅ {req['full_name']}'s request has been **approved** and the course has been updated.")
                    st.rerun()
                if c2.button("❌ Reject", key="re_"+req["request_id"], use_container_width=True):
                    out = review_course_change(user["user_id"], req["request_id"], False)
                    st.warning(f"❌ {req['full_name']}'s request has been **rejected**. No course change executed.")
                    st.rerun()

        # ── Audit log ─────────────────────────────────────────────────────────
        st.markdown('<div class="section-heading">📋 Audit Log</div>', unsafe_allow_html=True)
        if not audits:
            st.info("No audit events recorded yet.")
        else:
            # Build a human-readable dataframe
            rows = []
            for a in audits:
                rows.append({
                    "Timestamp":       _fmt_ts(a.get("timestamp","")),
                    "Actor":           a.get("actor_id","—"),
                    "Action":          _friendly_action(a.get("action","")),
                    "Target":          a.get("target_id","—") or "—",
                    "Decision":        _friendly_decision(a.get("decision","")),
                    "Approval Status": _friendly_approval(a.get("approval_status","")),
                    "Outcome":         (a.get("result","") or "—").replace("_"," ").title(),
                    "Details":         (a.get("details","") or "—"),
                })
            df_audit = pd.DataFrame(rows)

            def _colour_decision(val):
                if "Allowed" in str(val): return "color:#10b981;font-weight:600"
                if "Denied"  in str(val): return "color:#ef4444;font-weight:600"
                return ""

            styled = df_audit.style.map(_colour_decision, subset=["Decision"])
            st.dataframe(styled, use_container_width=True, hide_index=True, height=320)

        # ── Evaluation ────────────────────────────────────────────────────────
        st.markdown('<div class="section-heading">🧪 Assignment Evaluation</div>', unsafe_allow_html=True)
        if st.button("▶  Run 16 Assignment Checks", type="primary"):
            with st.spinner("Running evaluation suite…"):
                st.session_state.eval_results = run_evaluation()

        if "eval_results" in st.session_state:
            df = pd.DataFrame(st.session_state.eval_results)
            passed = int(df["Passed"].sum())
            total  = len(df)
            rate   = passed / total * 100

            e1, e2, e3 = st.columns(3)
            e1.metric("Tests Passed",   f"{passed} / {total}")
            e2.metric("Success Rate",   f"{rate:.1f}%")
            e3.metric("Tests Failed",   total - passed)

            def _colour_passed(val):
                if val is True:  return "background:#d1fae5;color:#065f46;font-weight:600"
                if val is False: return "background:#fee2e2;color:#991b1b;font-weight:600"
                return ""

            styled_eval = df.style.map(_colour_passed, subset=["Passed"])
            st.dataframe(styled_eval, use_container_width=True, hide_index=True)
        return

    # ══════════════════════════════════════════════════════════════════════════
    # STUDENT VIEW
    # ══════════════════════════════════════════════════════════════════════════

    rec = get_student_record(user["user_id"])

    # ── Student summary cards ──────────────────────────────────────────────────
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.markdown(f"""
        <div class="card">
          <div class="card-title">👤 Student ID</div>
          <div class="card-value" style="font-size:1.1rem">{user['user_id']}</div>
          <div class="card-sub">{user['name']}</div>
        </div>""", unsafe_allow_html=True)
    with s2:
        fee_val = rec.get("fee_status","—") if rec.get("ok") else "—"
        fee_col = "#ef4444" if "pending" in fee_val.lower() else "#10b981"
        st.markdown(f"""
        <div class="card">
          <div class="card-title">💰 Fee Status</div>
          <div class="card-value" style="font-size:0.95rem;color:{fee_col}">{fee_val}</div>
        </div>""", unsafe_allow_html=True)
    with s3:
        sch_val = rec.get("scholarship_status","—") if rec.get("ok") else "—"
        st.markdown(f"""
        <div class="card">
          <div class="card-title">🏅 Scholarship</div>
          <div class="card-value" style="font-size:0.85rem">{sch_val}</div>
        </div>""", unsafe_allow_html=True)
    with s4:
        prog = rec.get("programme","—") if rec.get("ok") else "—"
        st.markdown(f"""
        <div class="card">
          <div class="card-title">📚 Programme</div>
          <div class="card-value" style="font-size:0.85rem">{prog}</div>
        </div>""", unsafe_allow_html=True)

    # ── Student record + course-change requests ────────────────────────────────
    col_left, col_right = st.columns([1, 1])

    with col_left:
        with st.expander("📂 My Full Student Record", expanded=False):
            if rec.get("ok"):
                for label, val in [
                    ("Programme",       rec.get("programme","—")),
                    ("Current Course",  rec.get("current_course","—")),
                    ("Fee Status",      rec.get("fee_status","—")),
                    ("Scholarship",     rec.get("scholarship_status","—")),
                    ("Student ID",      rec.get("student_id","—")),
                ]:
                    st.markdown(f"""
                    <div class="info-row">
                      <span class="info-label">{label}</span>
                      <span class="info-value">{val}</span>
                    </div>""", unsafe_allow_html=True)
            else:
                st.warning("Record not available.")

    with col_right:
        with st.expander("🔄 My Course-Change Requests", expanded=False):
            requests = get_change_requests(user["user_id"])
            if not requests:
                st.info("No course-change requests submitted yet.")
            else:
                for r in requests:
                    status_html = _status_badge(r.get("status","—"))
                    ts = _fmt_ts(r.get("requested_at",""))
                    st.markdown(f"""
                    <div style="padding:8px 0;border-bottom:1px solid #f1f5f9">
                      <div style="display:flex;align-items:center;justify-content:space-between">
                        <span style="font-size:0.8rem;font-weight:700;color:#1e293b">{r.get('request_id','')}</span>
                        {status_html}
                      </div>
                      <div style="font-size:0.85rem;color:#475569;margin-top:3px">{r.get('requested_course','')}</div>
                      <div style="font-size:0.74rem;color:#94a3b8;margin-top:2px">{ts}</div>
                    </div>""", unsafe_allow_html=True)

    # ── Chat interface ─────────────────────────────────────────────────────────
    st.markdown('<div class="section-heading">💬 Ask the Student Support Agent</div>', unsafe_allow_html=True)

    # Suggested prompts (only when chat is empty)
    if not st.session_state.chat:
        st.markdown("**Suggested questions — click to send:**")
        p1, p2, p3, p4 = st.columns(4)
        suggestions = [
            ("💰", "What is my fee status?"),
            ("🏅", "What is my scholarship status?"),
            ("📜", "What does the policy say about late fee payment?"),
            ("🎓", "I want to change my course to Data Science"),
        ]
        for idx, (col, (icon, text)) in enumerate(zip([p1, p2, p3, p4], suggestions)):
            if col.button(f"{icon} {text}", use_container_width=True, key=f"sug_prompt_{idx}"):
                st.session_state.chat.append({"role": "user", "content": text})
                with st.spinner("Processing…"):
                    result = run_agent(user, text, use_llm=False)
                meta = f"Run: {result['run_id'][:8]} · Tools: {', '.join(result['tools']) or 'None'} · {result['latency_ms']:.1f} ms"
                if result["evidence"]: meta += " · Evidence: " + ", ".join(result["evidence"])
                st.session_state.chat.append({"role": "assistant", "content": result["answer"], "meta": meta})
                st.rerun()

    # Render history
    for item in st.session_state.chat:
        with st.chat_message(item["role"]):
            st.markdown(item["content"])
            if item.get("meta"):
                st.caption(item["meta"])

    if st.session_state.chat:
        if st.button("🗑️  Clear Conversation", key="clear_chat"):
            st.session_state.chat = []
            st.rerun()

    prompt = st.chat_input("Ask about fees, scholarships, policy, preferences, support tickets or course changes…")
    if prompt:
        st.session_state.chat.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant"):
            with st.spinner("Selecting and executing the appropriate tool…"):
                result = run_agent(user, prompt, use_llm=False)
            st.markdown(result["answer"])
            meta = f"Run: {result['run_id'][:8]} · Tools: {', '.join(result['tools']) or 'None'} · {result['latency_ms']:.1f} ms"
            if result["evidence"]: meta += " · Evidence: " + ", ".join(result["evidence"])
            st.caption(meta)
            st.session_state.chat.append({"role": "assistant", "content": result["answer"], "meta": meta})

    # ── Execution traces ────────────────────────────────────────────────────────
    with st.expander("🔍 My Execution Traces", expanded=False):
        traces = [x for x in get_recent_traces(100) if x["user_id"] == user["user_id"]]
        if not traces:
            st.info("No traces yet — start chatting to generate traces.")
        else:
            rows = []
            for t in traces:
                rows.append({
                    "Time":      _fmt_ts(t.get("timestamp","")),
                    "Turn":      t.get("turn_no","—"),
                    "Decision":  t.get("decision","—").replace("_"," ").title(),
                    "Tool":      t.get("tool_name","—") or "—",
                    "Summary":   t.get("result_summary","—") or "—",
                    "Latency":   f"{t.get('latency_ms',0):.1f} ms",
                    "Status":    t.get("status","—"),
                })
            df_traces = pd.DataFrame(rows)
            def _colour_status(val):
                if val == "ok": return "color:#10b981;font-weight:600"
                if "blocked" in str(val) or "error" in str(val): return "color:#ef4444;font-weight:600"
                return ""
            st.dataframe(df_traces.style.map(_colour_status, subset=["Status"]),
                         use_container_width=True, hide_index=True)

    # ── Architecture overview ───────────────────────────────────────────────────
    with st.expander("⚙️ Agent Architecture & Tool Registry", expanded=False):
        st.markdown("""
        **Request Flow**
        ```
        User Input
            → Sensitive-content filter
            → Bounded agent planner  (deterministic or Groq LLM)
            → Validated tool dispatcher
            → Authorization check (inside tool)
            → Observation / result
            → Formatted response
        ```
        **Available Tools**
        """)
        tools = [
            ("get_fee_status",         "💰", "Retrieve the signed-in student's own fee status."),
            ("get_scholarship_status", "🏅", "Retrieve scholarship eligibility and status."),
            ("get_student_record",     "📂", "Full student record (programme, course, fees, scholarship)."),
            ("search_policy",          "📜", "Keyword search over the institutional policy handbook."),
            ("get_memory",             "💾", "Retrieve saved non-sensitive preferences."),
            ("save_memory",            "✏️", "Persist whitelisted preferences (name, programme, comms)."),
            ("create_support_request", "🎫", "Open a support ticket and return a reference number."),
            ("request_course_change",  "🔄", "Submit a course-change request (pending admin approval)."),
        ]
        for name, icon, desc in tools:
            st.markdown(f"- **{icon} `{name}`** — {desc}")
        st.markdown("> Authorization is enforced inside each tool. Course changes require administrator approval before execution.")

if __name__ == "__main__":
    main()
