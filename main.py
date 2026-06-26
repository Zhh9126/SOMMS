import os
import sys
import time
import json
import threading
import schedule
import socket
import struct
import datetime
import subprocess
import shutil
from urllib.parse import urlparse
from tqdm import tqdm
from netaddr import IPNetwork, IPAddress
import dns.resolver
import requests
import paramiko
from peewee import SqliteDatabase, Model, CharField, IntegerField, DateTimeField, TextField, BooleanField, ForeignKeyField, PrimaryKeyField
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===================== 全局配置 =====================
VERSION = "v1.0.3"
DB_FILE = "sskit_data.db"
LOG_PATH = "audit_logs/"
REPORT_PATH = "scan_reports/"
DICT_PATH = "dicts/"
NUCLEI_TEMPLATE_PATH = "nuclei_templates/"
THREAD_NUM = 50
SCAN_TIMEOUT = 2

# 目录初始化
for p in [LOG_PATH, REPORT_PATH, DICT_PATH, NUCLEI_TEMPLATE_PATH]:
    if not os.path.exists(p):
        os.makedirs(p)

# 数据库初始化
db = SqliteDatabase(DB_FILE)

# ===================== 数据库模型层（修复自增主键） =====================
class BaseModel(Model):
    class Meta:
        database = db

# 1.资产表
class Asset(BaseModel):
    asset_id = CharField(primary_key=True)
    ip = CharField()
    domain = CharField(default="")
    asset_name = CharField()
    asset_type = CharField()  # host/web/db
    status = CharField(default="online")  # online/offline/change
    tag = CharField(default="")
    port_info = TextField(default="")
    service_finger = TextField(default="")
    create_time = DateTimeField(default=datetime.datetime.now)
    update_time = DateTimeField(default=datetime.datetime.now)

# 2.资产账号表（弱口令/SSH登录用）
class AssetAccount(BaseModel):
    id = PrimaryKeyField()
    asset = ForeignKeyField(Asset, on_delete="CASCADE")
    protocol = CharField()  # ssh/mysql/rdp/ftp
    username = CharField()
    password = CharField()
    port = IntegerField()

# 3.漏洞表
class Vulnerability(BaseModel):
    vuln_id = CharField(primary_key=True)
    asset = ForeignKeyField(Asset, on_delete="CASCADE")
    vuln_name = CharField()
    severity = CharField()  # high/mid/low
    poc_source = CharField()
    detail = TextField()
    status = CharField(default="found")  # found/fix/verify
    scan_time = DateTimeField(default=datetime.datetime.now)

# 4.操作审计日志
class AuditLog(BaseModel):
    log_id = PrimaryKeyField()
    operator = CharField(default="admin")
    operate_type = CharField()
    target = CharField()
    content = TextField()
    result = CharField()
    op_time = DateTimeField(default=datetime.datetime.now)

# 5.批量运维任务表
class BatchTask(BaseModel):
    task_id = CharField(primary_key=True)
    task_type = CharField()  # cmd/upload/file_dist
    target_asset_list = TextField()
    cmd_content = TextField(default="")
    file_path = TextField(default="")
    schedule_time = CharField(default="")
    status = CharField(default="pending")
    create_time = DateTimeField(default=datetime.datetime.now)

# 创建数据表
db.create_tables([Asset, AssetAccount, Vulnerability, AuditLog, BatchTask])

# ===================== 通用工具函数 =====================
def write_audit_log(op_type, target, content, result):
    """写入审计日志（日志审计模块核心）"""
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
    """生成唯一ID"""
    import uuid
    return str(uuid.uuid4())

def save_json_report(data, name):
    """导出扫描报告"""
    file = os.path.join(REPORT_PATH, f"{name}_{int(time.time())}.json")
    with open(file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[+] 报告已保存：{file}")
    return file

# ===================== 模块1：资产管理模块 =====================
class AssetManager:
    @staticmethod
    def add_asset(ip, domain, name, asset_type, tag=""):
        aid = generate_uuid()
        Asset.create(
            asset_id=aid,
            ip=ip,
            domain=domain,
            asset_name=name,
            asset_type=asset_type,
            tag=tag
        )
        write_audit_log("资产新增", ip, f"新增资产{name}", "成功")
        return aid

    @staticmethod
    def batch_import_asset(file_path):
        """批量导入资产（csv/json）"""
        res = {"success":0, "fail":0}
        if file_path.endswith(".json"):
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data:
                try:
                    AssetManager.add_asset(
                        ip=item["ip"],
                        domain=item.get("domain", ""),
                        name=item["name"],
                        asset_type=item["type"],
                        tag=item.get("tag", "")
                    )
                    res["success"] +=1
                except:
                    res["fail"] +=1
        write_audit_log("批量导入资产", file_path, f"成功{res['success']} 失败{res['fail']}", "完成")
        return res

    @staticmethod
    def export_all_asset():
        assets = Asset.select().dicts()
        save_json_report(list(assets), "asset_all")
        write_audit_log("资产导出", "全部资产", "导出全量资产档案", "成功")
        return list(assets)

    @staticmethod
    def update_asset_tag(aid, new_tag):
        asset = Asset.get_by_id(aid)
        asset.tag = new_tag
        asset.update_time = datetime.datetime.now()
        asset.save()
        write_audit_log("资产标签修改", aid, f"更新标签为{new_tag}", "成功")

    @staticmethod
    def offline_asset(aid):
        asset = Asset.get_by_id(aid)
        asset.status = "offline"
        asset.save()
        write_audit_log("资产下线", aid, "标记资产下线", "成功")

# ===================== 模块2：漏洞全生命周期管理 =====================
class VulnManager:
    @staticmethod
    def add_vuln(asset_id, vuln_name, severity, poc_source, detail):
        vid = generate_uuid()
        Vulnerability.create(
            vuln_id=vid,
            asset=asset_id,
            vuln_name=vuln_name,
            severity=severity,
            poc_source=poc_source,
            detail=detail
        )
        write_audit_log("漏洞录入", asset_id, f"新增漏洞{vuln_name}", "成功")
        return vid

    @staticmethod
    def vuln_fix(vid):
        vuln = Vulnerability.get_by_id(vid)
        vuln.status = "fix"
        vuln.save()
        write_audit_log("漏洞修复标记", vid, "标记漏洞已修复", "成功")

    @staticmethod
    def vuln_verify(vid):
        vuln = Vulnerability.get_by_id(vid)
        vuln.status = "verify"
        vuln.save()
        write_audit_log("漏洞复测验证", vid, "漏洞复测无风险", "完成")

    @staticmethod
    def stat_vuln():
        high = Vulnerability.select().where(Vulnerability.severity=="high").count()
        mid = Vulnerability.select().where(Vulnerability.severity=="mid").count()
        low = Vulnerability.select().where(Vulnerability.severity=="low").count()
        found = Vulnerability.select().where(Vulnerability.status=="found").count()
        fix = Vulnerability.select().where(Vulnerability.status=="fix").count()
        return {"high":high, "mid":mid, "low":low, "unfixed":found, "fixed":fix}

# ===================== 模块3：资产测绘（主机测绘+应用测绘） =====================
class AssetScan:
    common_ports = [21,22,23,80,443,3306,3389,8080,7001,6379,8000,8090,9090]
    sub_dict = ["www","admin","api","test","dev","oa","mail","ftp","vpn","cdn","app","manage"]
    dir_dict = ["/admin","/api","/phpmyadmin","/robots.txt","/config","/backup"]

    @staticmethod
    def ip_range_expand(target):
        """解析IP段 192.168.1.0/24 192.168.1.1-192.168.1.10"""
        ips = []
        if "/" in target:
            net = IPNetwork(target)
            for ip in net:
                ips.append(str(ip))
        elif "-" in target:
            start, end = target.split("-")
            s = struct.unpack("!I", socket.inet_aton(start))[0]
            e = struct.unpack("!I", socket.inet_aton(end))[0]
            for i in range(s, e+1):
                ips.append(socket.inet_ntoa(struct.pack("!I", i)))
        else:
            ips.append(target)
        return ips

    @staticmethod
    def ping_alive(ip):
        """存活探测（Windows适配）"""
        try:
            subprocess.check_output(["ping","-n","1","-w","1000",ip], stderr=subprocess.STDOUT)
            return True
        except:
            return False

    @staticmethod
    def port_single_scan(ip, port):
        s = socket.socket()
        s.settimeout(SCAN_TIMEOUT)
        res = s.connect_ex((ip, port))
        if res == 0:
            try:
                banner = s.recv(1024).decode("utf8", errors="ignore").strip()
            except:
                banner = ""
            s.close()
            return {"port":port, "open":True, "banner":banner}
        s.close()
        return {"port":port, "open":False, "banner":""}

    def host_scan(self, target_ip_range):
        """主机测绘：IP段存活+端口扫描"""
        all_ips = self.ip_range_expand(target_ip_range)
        scan_result = []
        alive_hosts = []
        print(f"[*] 共{len(all_ips)}个IP，开始存活探测")
        for ip in tqdm(all_ips):
            if self.ping_alive(ip):
                alive_hosts.append(ip)
                port_data = []
                for p in self.common_ports:
                    ret = self.port_single_scan(ip, p)
                    if ret["open"]:
                        port_data.append(ret)
                scan_result.append({"ip":ip, "ports":port_data})
                # 自动入库资产
                port_str = json.dumps(port_data, ensure_ascii=False)
                AssetManager.add_asset(ip, "", f"主机_{ip}", "host", "自动测绘")
                asset = Asset.get(Asset.ip==ip)
                asset.port_info = port_str
                asset.save()
        write_audit_log("主机资产测绘", target_ip_range, f"发现存活主机{len(alive_hosts)}台", "完成")
        save_json_report(scan_result, "host_scan")
        return scan_result

    def subdomain_brute(self, domain):
        """子域名爆破"""
        sub_res = []
        for sub in self.sub_dict:
            d = f"{sub}.{domain}"
            try:
                ans = dns.resolver.resolve(d, "A")
                ip_list = [str(i) for i in ans]
                sub_res.append({"subdomain":d, "ips":ip_list})
                # 自动入库WEB资产
                AssetManager.add_asset(ip_list[0], d, f"WEB_{d}", "web", "子域测绘")
            except Exception:
                continue
        write_audit_log("子域名测绘", domain, f"发现子域{len(sub_res)}个", "完成")
        return sub_res

    def dir_scan(self, url):
        """目录爆破"""
        dir_res = []
        for d in self.dir_dict:
            full = url + d
            try:
                r = requests.get(full, timeout=2, verify=False)
                if r.status_code in [200,403]:
                    dir_res.append({"path":full, "status":r.status_code})
            except:
                continue
        return dir_res

    def web_finger(self, url):
        """WEB指纹识别"""
        try:
            r = requests.get(url, timeout=3, verify=False)
            headers = str(r.headers)
            server = r.headers.get("Server", "")
            return {"server":server, "header_raw":headers, "status":r.status_code}
        except:
            return {}

    def app_scan(self, domain):
        """应用测绘完整流程：子域+端口+目录+指纹"""
        full_result = {}
        subs = self.subdomain_brute(domain)
        full_result["subdomains"] = subs
        web_data = []
        for sub_info in subs:
            sub = sub_info["subdomain"]
            ip = sub_info["ips"][0]
            url = f"http://{sub}"
            ports = []
            for p in self.common_ports:
                ret = self.port_single_scan(ip, p)
                if ret["open"]:
                    ports.append(ret)
            dirs = self.dir_scan(url)
            finger = self.web_finger(url)
            web_data.append({
                "subdomain":sub,
                "ip":ip,
                "ports":ports,
                "dirs":dirs,
                "finger":finger
            })
        full_result["web_assets"] = web_data
        save_json_report(full_result, "app_scan")
        write_audit_log("应用资产测绘", domain, f"测绘WEB资产{len(web_data)}个", "完成")
        return full_result

# ===================== 模块4：等保2.0配置核查（SSH无代理） =====================
class ConfigCheck:
    linux_check_items = [
        {"name":"SSH弱密码允许", "cmd":"grep PermitEmptyPasswords /etc/ssh/sshd_config"},
        {"name":"root远程登录", "cmd":"grep PermitRootLogin /etc/ssh/sshd_config"},
        {"name":"密码认证开启", "cmd":"grep PasswordAuthentication /etc/ssh/sshd_config"},
        {"name":"防火墙状态", "cmd":"systemctl status firewalld || ufw status"},
        {"name":"登录审计日志", "cmd":"cat /var/log/secure | head -10"},
    ]
    windows_check_items = [
        {"name":"远程桌面开启", "cmd":"qwinsta"},
        {"name":"管理员弱口令策略", "cmd":"net accounts"},
        {"name":"防火墙配置", "cmd":"netsh advfirewall show allprofiles"},
    ]

    def ssh_exec(self, ip, port, user, pwd, cmd):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, port=port, username=user, password=pwd, timeout=5)
            stdin, stdout, stderr = ssh.exec_command(cmd)
            out = stdout.read().decode("utf8", errors="ignore")
            err = stderr.read().decode("utf8", errors="ignore")
            ssh.close()
            return {"success":True, "output":out, "error":err}
        except Exception as e:
            return {"success":False, "msg":str(e)}

    def check_linux(self, ip, port, user, pwd):
        result = []
        for item in self.linux_check_items:
            ret = self.ssh_exec(ip, port, user, pwd, item["cmd"])
            result.append({
                "check_name":item["name"],
                "cmd":item["cmd"],
                "scan_result":ret
            })
        write_audit_log("Linux配置核查", ip, f"完成{len(result)}项等保检查", "完成")
        save_json_report(result, f"linux_config_{ip}")
        return result

    def check_windows(self, ip, port, user, pwd):
        result = []
        for item in self.windows_check_items:
            ret = self.ssh_exec(ip, port, user, pwd, item["cmd"])
            result.append({
                "check_name":item["name"],
                "cmd":item["cmd"],
                "scan_result":ret
            })
        write_audit_log("Windows配置核查", ip, f"完成{len(result)}项等保检查", "完成")
        save_json_report(result, f"win_config_{ip}")
        return result

# ===================== 模块5：Nuclei漏洞检测 =====================
class NucleiScan:
    def scan_target(self, target_list, template_path=None):
        """基于nuclei二进制程序批量漏洞扫描"""
        if shutil.which("nuclei") is None:
            print("[错误] 未找到nuclei程序，请下载nuclei并配置系统环境变量！")
            return []
        if not template_path:
            template_path = NUCLEI_TEMPLATE_PATH
        report_data = []
        for target in target_list:
            target = target.strip()
            if not target:
                continue
            cmd = ["nuclei", "-u", target, "-t", template_path, "-json"]
            try:
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=300)
                lines = output.decode("utf8", errors="ignore").splitlines()
                for line in lines:
                    if line.strip():
                        vuln_data = json.loads(line)
                        report_data.append(vuln_data)
                        # 漏洞入库
                        netloc = urlparse(target).netloc
                        ip = netloc.split(":")[0] if ":" in netloc else netloc
                        asset = Asset.select().where(Asset.ip==ip).first()
                        if asset:
                            VulnManager.add_vuln(
                                asset_id=asset.asset_id,
                                vuln_name=vuln_data.get("info",{}).get("name","未知漏洞"),
                                severity=vuln_data.get("info",{}).get("severity","low"),
                                poc_source="nuclei模板",
                                detail=json.dumps(vuln_data, ensure_ascii=False)
                            )
            except Exception as e:
                print(f"[-] {target} 扫描异常：{str(e)}")
        save_json_report(report_data, "nuclei_vuln_scan")
        write_audit_log("Nuclei漏洞扫描", str(target_list), f"扫描发现漏洞{len(report_data)}条", "完成")
        return report_data

# ===================== 模块6：弱口令爆破 =====================
class WeakPassCracker:
    protocols = {
        "ssh":22, "mysql":3306, "ftp":21, "telnet":23, "rdp":3389, "pop3":110
    }
    user_dict = ["root","admin","test","user","guest"]
    pass_dict = ["123456","root","admin","123123","password","123321"]

    def crack_ssh(self, ip, port, user, pwd):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port, user, pwd, timeout=2)
            ssh.close()
            return True
        except:
            return False

    def brute_target(self, ip, proto):
        port = self.protocols.get(proto)
        if not port:
            print(f"不支持协议 {proto}")
            return []
        hit = []
        for u in self.user_dict:
            for p in self.pass_dict:
                if proto == "ssh":
                    if self.crack_ssh(ip, port, u, p):
                        hit.append({"proto":proto, "user":u, "pass":p, "port":port})
                        asset = Asset.select().where(Asset.ip==ip).first()
                        if asset:
                            AssetAccount.create(asset=asset.asset_id, protocol=proto, username=u, password=p, port=port)
        write_audit_log(f"{proto}弱口令爆破", ip, f"命中弱口令{len(hit)}组", "完成")
        return hit

# ===================== 模块7：在线SSH主机运维终端 =====================
class SSHTerminal:
    def connect_asset_ssh(self, asset_id):
        acc_list = AssetAccount.select().where(AssetAccount.asset==asset_id, AssetAccount.protocol=="ssh")
        asset = Asset.get_by_id(asset_id)
        if not acc_list:
            print("[-] 该资产未录入SSH账号")
            return
        acc = acc_list[0]
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(asset.ip, port=acc.port, username=acc.username, password=acc.password)
        print(f"[+] 成功连接 {asset.ip} SSH终端，输入exit退出")
        write_audit_log("SSH在线终端登录", asset.asset_id, f"账号{acc.username}登录", "成功")
        while True:
            cmd = input(f"[{asset.ip}]$ ")
            if cmd.lower() == "exit":
                ssh.close()
                break
            stdin, stdout, stderr = ssh.exec_command(cmd)
            out = stdout.read().decode("utf8", errors="ignore")
            err = stderr.read().decode("utf8", errors="ignore")
            print(out)
            if err:
                print("ERR:", err)
            write_audit_log("SSH终端执行命令", asset.ip, f"执行：{cmd}", "正常返回")

# ===================== 模块8：批量运维 =====================
class BatchOps:
    def batch_run_cmd(self, asset_id_list, cmd):
        tid = generate_uuid()
        BatchTask.create(
            task_id=tid,
            task_type="batch_cmd",
            target_asset_list=json.dumps(asset_id_list),
            cmd_content=cmd
        )
        success = 0
        for aid in asset_id_list:
            aid = aid.strip()
            if not aid:
                continue
            asset = Asset.get_by_id(aid)
            acc = AssetAccount.select().where(AssetAccount.asset==aid, AssetAccount.protocol=="ssh").first()
            if not acc:
                print(f"[-] 资产{aid}无SSH账号，跳过")
                continue
            cfg = ConfigCheck()
            ret = cfg.ssh_exec(asset.ip, acc.port, acc.username, acc.password, cmd)
            if ret["success"]:
                success +=1
        task = BatchTask.get_by_id(tid)
        task.status = "finish"
        task.save()
        write_audit_log("批量命令执行", str(asset_id_list), f"成功{success}台主机执行命令:{cmd}", "完成")
        return {"task_id":tid, "success_count":success}

    def batch_upload_file(self, asset_id_list, local_file, remote_path):
        tid = generate_uuid()
        BatchTask.create(
            task_id=tid,
            task_type="file_dist",
            target_asset_list=json.dumps(asset_id_list),
            file_path=f"{local_file}->{remote_path}"
        )
        if not os.path.exists(local_file):
            print(f"本地文件不存在：{local_file}")
            return {"task_id":tid, "success_count":0}
        success = 0
        for aid in asset_id_list:
            aid = aid.strip()
            if not aid:
                continue
            asset = Asset.get_by_id(aid)
            acc = AssetAccount.select().where(AssetAccount.asset==aid, AssetAccount.protocol=="ssh").first()
            if not acc:
                print(f"[-] 资产{aid}无SSH账号，跳过")
                continue
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(asset.ip, acc.port, acc.username, acc.password, timeout=5)
                sftp = ssh.open_sftp()
                sftp.put(local_file, remote_path)
                sftp.close()
                ssh.close()
                success +=1
            except Exception as e:
                print(f"[-] {asset.ip} 文件分发失败 {e}")
        task = BatchTask.get_by_id(tid)
        task.status = "finish"
        task.save()
        write_audit_log("批量文件分发", str(asset_id_list), f"本地{local_file}推送至{remote_path}，成功{success}", "完成")
        return {"task_id":tid, "success_count":success}

    def schedule_task(self, task_func, cron_time):
        """定时调度任务"""
        schedule.every().day.at(cron_time).do(task_func)
        def run_loop():
            while True:
                schedule.run_pending()
                time.sleep(60)
        threading.Thread(target=run_loop, daemon=True).start()
        print(f"[+] 定时任务已开启，每日{cron_time}执行")

# ===================== 主交互控制台 =====================
def main():
    asset_mgr = AssetManager()
    vuln_mgr = VulnManager()
    scan_tool = AssetScan()
    cfg_check = ConfigCheck()
    nuclei = NucleiScan()
    cracker = WeakPassCracker()
    ssh_term = SSHTerminal()
    batch_ops = BatchOps()

    print("="*60)
    print(f"        SSKit 安全运维工具箱 {VERSION}")
    print("  资产测绘 | 漏洞管理 | 配置核查 | 弱口令爆破 | 批量运维")
    print("="*60)
    while True:
        print("""
【1】资产管理
【2】漏洞全生命周期管理
【3】资产测绘（主机/应用扫描）
【4】等保2.0配置核查
【5】Nuclei漏洞扫描
【6】弱口令爆破
【7】在线SSH终端运维
【8】批量运维（命令/文件分发/定时任务）
【9】日志审计查看
【0】退出程序
        """)
        opt = input("请输入功能序号：")
        if opt == "1":
            print("\n1.新增资产 2.批量导入 3.导出资产 4.资产下线 5.修改标签")
            sub = input("子功能：")
            if sub == "1":
                ip = input("IP：")
                dom = input("域名：")
                name = input("资产名称：")
                typ = input("类型(host/web/db)：")
                asset_mgr.add_asset(ip, dom, name, typ)
            elif sub == "2":
                fp = input("导入文件路径(json)：")
                print(asset_mgr.batch_import_asset(fp))
            elif sub == "3":
                asset_mgr.export_all_asset()
            elif sub == "4":
                aid = input("资产ID：")
                asset_mgr.offline_asset(aid)
            elif sub == "5":
                aid = input("资产ID：")
                tag = input("新标签：")
                asset_mgr.update_asset_tag(aid, tag)

        elif opt == "2":
            print("\n1.漏洞统计 2.标记修复 3.复测验证")
            sub = input("子功能：")
            if sub == "1":
                print(vuln_mgr.stat_vuln())
            elif sub == "2":
                vid = input("漏洞ID：")
                vuln_mgr.vuln_fix(vid)
            elif sub == "3":
                vid = input("漏洞ID：")
                vuln_mgr.vuln_verify(vid)

        elif opt == "3":
            print("\n1.主机测绘(IP段) 2.应用测绘(域名子域)")
            sub = input("子功能：")
            if sub == "1":
                target = input("输入IP/网段(192.168.1.0/24)：")
                scan_tool.host_scan(target)
            elif sub == "2":
                dom = input("输入主域名(baidu.com)：")
                scan_tool.app_scan(dom)

        elif opt == "4":
            ip = input("目标IP：")
            port = int(input("SSH端口："))
            user = input("账号：")
            pwd = input("密码：")
            sys_type = input("系统类型 linux/windows：")
            if sys_type == "linux":
                cfg_check.check_linux(ip, port, user, pwd)
            else:
                cfg_check.check_windows(ip, port, user, pwd)

        elif opt == "5":
            targets = input("目标列表(逗号分隔url/ip)：").split(",")
            nuclei.scan_target(targets)

        elif opt == "6":
            ip = input("目标IP：")
            proto = input("协议(ssh/mysql/ftp/telnet)：")
            cracker.brute_target(ip, proto)

        elif opt == "7":
            aid = input("资产ID：")
            ssh_term.connect_asset_ssh(aid)

        elif opt == "8":
            print("\n1.批量执行命令 2.批量文件分发 3.开启定时任务")
            sub = input("子功能：")
            if sub == "1":
                aids = input("资产ID列表逗号分隔：").split(",")
                cmd = input("执行命令：")
                print(batch_ops.batch_run_cmd(aids, cmd))
            elif sub == "2":
                aids = input("资产ID列表逗号分隔：").split(",")
                lf = input("本地文件路径：")
                rf = input("远程保存路径：")
                print(batch_ops.batch_upload_file(aids, lf, rf))
            elif sub == "3":
                cron = input("每日定时时间(02:00)：")
                batch_ops.schedule_task(lambda: print("定时任务执行完成"), cron)

        elif opt == "9":
            log_file = os.path.join(LOG_PATH, f"{datetime.date.today()}.log")
            if os.path.exists(log_file):
                with open(log_file, "r", encoding="utf8") as f:
                    print(f.read())
            else:
                print("今日暂无审计日志")

        elif opt == "0":
            print("程序退出，所有数据保存在sskit_data.db")
            sys.exit(0)
        input("\n回车返回主菜单...")

if __name__ == "__main__":
    main()