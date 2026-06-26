import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "sskit_data.db")
LOG_PATH = os.path.join(BASE_DIR, "audit_logs/")
REPORT_PATH = os.path.join(BASE_DIR, "scan_reports/")
DICT_PATH = os.path.join(BASE_DIR, "dicts/")
NUCLEI_TEMPLATE_PATH = os.path.join(BASE_DIR, "nuclei_templates/")   # 保留有效路径

THREAD_NUM = 50
SCAN_TIMEOUT = 2

# 确保目录存在（跳过空字符串）
for p in [LOG_PATH, REPORT_PATH, DICT_PATH, NUCLEI_TEMPLATE_PATH]:
    if p:  # 仅当路径非空时创建
        os.makedirs(p, exist_ok=True)