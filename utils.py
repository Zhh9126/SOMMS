import os
import json
import datetime
import uuid
import time
from models import AuditLog
from config import LOG_PATH, REPORT_PATH

def write_audit_log(op_type, target, content, result):
    AuditLog.create(
        operate_type=op_type,
        target=target,
        content=content,
        result=result
    )
    log_file = os.path.join(LOG_PATH, f"{datetime.date.today()}.log")
    log_text = f"[{datetime.datetime.now()}] TYPE:{op_type} TARGET:{target} CONTENT:{content} RESULT:{result}\n"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_text)

def generate_uuid():
    return str(uuid.uuid4())

def save_json_report(data, name):
    file = os.path.join(REPORT_PATH, f"{name}_{int(time.time())}.json")
    with open(file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return file