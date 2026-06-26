import datetime
from peewee import SqliteDatabase, Model, CharField, IntegerField, DateTimeField, TextField, BooleanField, ForeignKeyField, PrimaryKeyField
from config import DB_FILE

db = SqliteDatabase(DB_FILE)

class BaseModel(Model):
    class Meta:
        database = db

class Asset(BaseModel):
    asset_id = CharField(primary_key=True)
    ip = CharField()
    domain = CharField(default="")
    asset_name = CharField()
    asset_type = CharField()  # host/web/db
    status = CharField(default="online")
    tag = CharField(default="")
    port_info = TextField(default="")
    service_finger = TextField(default="")
    create_time = DateTimeField(default=datetime.datetime.now)
    update_time = DateTimeField(default=datetime.datetime.now)

class AssetAccount(BaseModel):
    id = PrimaryKeyField()
    asset = ForeignKeyField(Asset, on_delete="CASCADE")
    protocol = CharField()
    username = CharField()
    password = CharField()
    port = IntegerField()

class Vulnerability(BaseModel):
    vuln_id = CharField(primary_key=True)
    asset = ForeignKeyField(Asset, on_delete="CASCADE")
    vuln_name = CharField()
    severity = CharField()
    poc_source = CharField()
    detail = TextField()
    status = CharField(default="found")
    scan_time = DateTimeField(default=datetime.datetime.now)

class AuditLog(BaseModel):
    log_id = PrimaryKeyField()
    operator = CharField(default="admin")
    operate_type = CharField()
    target = CharField()
    content = TextField()
    result = CharField()
    op_time = DateTimeField(default=datetime.datetime.now)

class BatchTask(BaseModel):
    task_id = CharField(primary_key=True)
    task_type = CharField()
    target_asset_list = TextField()
    cmd_content = TextField(default="")
    file_path = TextField(default="")
    schedule_time = CharField(default="")
    status = CharField(default="pending")
    create_time = DateTimeField(default=datetime.datetime.now)

# 任务记录（用于异步任务状态追踪）
class TaskRecord(BaseModel):
    task_id = CharField(primary_key=True)
    task_type = CharField()          # host_scan, app_scan, config_check, nuclei, weakpass
    target = CharField()
    status = CharField(default="running")  # running, finished, error
    result = TextField(default="")
    create_time = DateTimeField(default=datetime.datetime.now)
    finish_time = DateTimeField(null=True)

db.create_tables([Asset, AssetAccount, Vulnerability, AuditLog, BatchTask, TaskRecord], safe=True)
from werkzeug.security import generate_password_hash, check_password_hash

from werkzeug.security import generate_password_hash, check_password_hash

class User(BaseModel):
    id = PrimaryKeyField()
    username = CharField(unique=True)
    password_hash = CharField()
    created_at = DateTimeField(default=datetime.datetime.now)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 创建表（如果尚未存在）
db.create_tables([User], safe=True)