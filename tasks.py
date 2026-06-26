import time
import json
import threading
import socket
import struct
import subprocess
import shutil
import datetime
import logging
import os
import re
import tempfile
from urllib.parse import urlparse
from netaddr import IPNetwork
import dns.resolver
import requests
import paramiko
from models import Asset, AssetAccount, Vulnerability, TaskRecord
from utils import write_audit_log, generate_uuid, save_json_report
from config import SCAN_TIMEOUT, NUCLEI_TEMPLATE_PATH

# 彻底禁用 paramiko 日志（避免刷屏）
paramiko.util.log_to_file(os.devnull)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

# 资产扫描相关通用函数
common_ports = [21, 22, 23, 80, 443, 3306, 3389, 8080, 7001, 6379, 8000, 8090, 9090]

def ip_range_expand(target):
    ips = []
    if "/" in target:
        net = IPNetwork(target)
        for ip in net:
            ips.append(str(ip))
    elif "-" in target:
        start, end = target.split("-")
        s = struct.unpack("!I", socket.inet_aton(start))[0]
        e = struct.unpack("!I", socket.inet_aton(end))[0]
        for i in range(s, e + 1):
            ips.append(socket.inet_ntoa(struct.pack("!I", i)))
    else:
        ips.append(target)
    return ips

def ping_alive(ip):
    try:
        subprocess.check_output(["ping", "-n", "1", "-w", "1000", ip], stderr=subprocess.STDOUT)
        return True
    except:
        return False

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
        return {"port": port, "open": True, "banner": banner}
    s.close()
    return {"port": port, "open": False, "banner": ""}

# ---------- 异步任务函数 ----------
def async_host_scan(task_id, target_ip_range):
    """主机测绘 - 修复状态更新"""
    try:
        all_ips = ip_range_expand(target_ip_range)
        scan_result = []
        alive_hosts = []
        total = len(all_ips)
        logger = logging.getLogger(__name__)
        logger.info(f"[Scan] 开始扫描 {total} 个IP，任务ID: {task_id}")
        
        for idx, ip in enumerate(all_ips):
            if idx % 10 == 0:
                logger.info(f"[Scan] 进度: {idx+1}/{total}")
            if ping_alive(ip):
                alive_hosts.append(ip)
                port_data = []
                for p in common_ports:
                    ret = port_single_scan(ip, p)
                    if ret["open"]:
                        port_data.append(ret)
                scan_result.append({"ip": ip, "ports": port_data})
                # 自动入库资产
                aid = generate_uuid()
                Asset.create(
                    asset_id=aid,
                    ip=ip,
                    domain="",
                    asset_name=f"主机_{ip}",
                    asset_type="host",
                    tag="自动测绘",
                    port_info=json.dumps(port_data, ensure_ascii=False)
                )
        
        save_json_report(scan_result, f"host_scan_{task_id}")
        write_audit_log("主机资产测绘", target_ip_range, f"发现存活主机{len(alive_hosts)}台", "完成")
        TaskRecord.update(status="finished", result=json.dumps(scan_result), finish_time=datetime.datetime.now()).where(TaskRecord.task_id == task_id).execute()
        logger.info(f"[Scan] 任务完成: {task_id}, 存活主机 {len(alive_hosts)} 台")
        
    except Exception as e:
        TaskRecord.update(status="error", result=str(e)).where(TaskRecord.task_id == task_id).execute()
        logging.error(f"[Scan] 任务失败: {task_id}, 错误: {e}")

def async_app_scan(task_id, domain):
    """应用测绘 - 增强版"""
    try:
        logger = logging.getLogger(__name__)
        logger.info(f"[AppScan] 开始测绘域名: {domain}")

        # ---------- 1. 准备字典 ----------
        sub_list = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
            "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3",
            "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old",
            "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure",
            "demo", "cp", "calendar", "wiki", "web", "media", "email", "images", "img", "download",
            "dns", "piwik", "stats", "dashboard", "portal", "manage", "start", "info", "help",
            "software", "status", "api", "app", "apps", "cdn", "files", "video", "music", "stream",
            "upload", "downloads", "backup", "git", "svn", "jenkins", "jira", "confluence", "sonar",
            "nexus", "artifactory", "registry", "docker", "k8s", "kubernetes", "openshift", "rancher",
            "prometheus", "grafana", "elk", "kibana", "logstash", "elasticsearch", "kafka", "zookeeper",
            "hadoop", "spark", "flink", "hive", "hbase", "cassandra", "mongodb", "redis", "memcached",
            "rabbitmq", "activemq", "tomcat", "weblogic", "jboss", "glassfish", "jetty", "wildfly",
            "nginx", "apache", "lighttpd", "caddy", "traefik", "haproxy", "squid", "varnish",
            "ftp", "sftp", "rsync", "nfs", "smb", "cifs", "iscsi", "snmp", "syslog", "ntp",
            "ldap", "kerberos", "radius", "tacacs", "diameter", "sip", "h323", "rtsp", "mms",
            "xmpp", "jabber", "irc", "weechat", "mattermost", "rocketchat", "zulip", "riot",
            "matrix", "synapse", "element", "wire", "signal", "telegram", "whatsapp", "line",
            "wechat", "qq", "skype", "teams", "slack", "discord", "gitter", "freenode",
            "bitbucket", "github", "gitlab", "gitea", "gogs", "sourcehut", "codeberg", "framagit",
            "inbox", "outlook", "exchange", "zimbra", "roundcube", "squirrelmail", "rainloop",
            "wordpress", "joomla", "drupal", "magento", "shopify", "woocommerce", "prestashop",
            "opencart", "xcart", "oscommerce", "zen-cart", "virtuemart", "spree", "solidus",
            "phpmyadmin", "phpldapadmin", "phpPgAdmin", "phppgadmin", "adminer", "webmin",
            "usermin", "virtualmin", "vestacp", "ispconfig", "zpanel", "sentora", "kloxo",
            "directadmin", "cwp", "centos-webpanel", "ajenti", "froxlor", "ispcp", "ehcp",
            "tine20", "opengoo", "collabtive", "dotproject", "web2project", "activecollab",
            "redmine", "trac", "bugzilla", "mantis", "flyspray", "eventum", "zendesk", "freshdesk",
            "osTicket", "osticket", "zoho", "salesforce", "hubspot", "insightly", "pipedrive",
            "moodle", "canvas", "blackboard", "sakai", "chamilo", "claroline", "ilias", "opigno",
            "bigbluebutton", "jitsi", "meet", "talk", "firefox", "chrome", "opera", "safari",
            "edge", "vivaldi", "brave", "tor", "i2p", "freenet", "zeronet", "ipfs", "filecoin",
            "ethereum", "bitcoin", "monero", "dogecoin", "litecoin", "zcash", "dash", "ripple",
            "stellar", "cardano", "polkadot", "kusama", "cosmos", "tendermint", "solana",
            "near", "avalanche", "fantom", "harmony", "elrond", "tezos", "algorand", "iota",
            "nano", "raiblocks", "ravencoin", "grin", "beam", "safepal", "ledger", "trezor"
        ]
        dir_list = [
            "/admin", "/administrator", "/login", "/wp-login.php", "/wp-admin", "/cpanel",
            "/webmail", "/phpmyadmin", "/phpMyAdmin", "/pma", "/mysql", "/db", "/database",
            "/sql", "/myadmin", "/adminer", "/phpPgAdmin", "/phppgadmin", "/pgadmin",
            "/server-status", "/server-info", "/status", "/info", "/phpinfo.php", "/info.php",
            "/test", "/tests", "/tmp", "/temp", "/backup", "/backups", "/old", "/new",
            "/dev", "/beta", "/alpha", "/stage", "/staging", "/prod", "/production",
            "/api", "/v1", "/v2", "/v3", "/rest", "/graphql", "/swagger", "/swagger-ui",
            "/docs", "/documentation", "/help", "/faq", "/about", "/contact", "/support",
            "/download", "/downloads", "/files", "/uploads", "/images", "/img", "/css",
            "/js", "/jsmin", "/lib", "/vendor", "/node_modules", "/bower_components",
            "/wp-content", "/wp-includes", "/wp-json", "/wp-cron.php", "/xmlrpc.php",
            "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/crossdomain.xml",
            "/clientaccesspolicy.xml", "/web.config", "/.env", "/.git", "/.svn", "/.htaccess",
            "/.htpasswd", "/.bashrc", "/.profile", "/.ssh", "/.aws", "/.azure", "/.gcp",
            "/config", "/conf", "/settings", "/configuration", "/env", "/prod.env", "/dev.env"
        ]

        # ---------- 2. 获取主域名 IP ----------
        try:
            main_ip = socket.gethostbyname(domain)
            logger.info(f"[AppScan] 主域名解析: {domain} -> {main_ip}")
        except:
            main_ip = None
            logger.warning(f"[AppScan] 无法解析主域名: {domain}")

        # ---------- 3. 子域爆破 ----------
        subdomains_found = []
        if main_ip:
            subdomains_found.append({"subdomain": domain, "ip": main_ip, "source": "main"})

        for sub in sub_list:
            full_domain = f"{sub}.{domain}"
            try:
                ips = socket.gethostbyname_ex(full_domain)
                ip_list = list(set(ips[2]))
                for ip in ip_list:
                    subdomains_found.append({"subdomain": full_domain, "ip": ip, "source": "brute"})
                logger.debug(f"[AppScan] 发现子域: {full_domain} -> {ip_list}")
            except:
                continue

        logger.info(f"[AppScan] 共发现 {len(subdomains_found)} 个子域（含主域名）")

        # ---------- 4. 服务端口映射 ----------
        service_port_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5900: "vnc", 6379: "redis",
            7001: "weblogic", 8000: "http-alt", 8080: "http-proxy",
            8443: "https-alt", 8888: "http-alt", 9090: "http-admin",
            9200: "elasticsearch", 9300: "elasticsearch", 27017: "mongodb"
        }

        # ---------- 5. 对每个子域进行端口扫描和 Web 探测 ----------
        all_assets = []
        for sub_item in subdomains_found:
            sub_domain = sub_item["subdomain"]
            ip = sub_item["ip"]
            source = sub_item["source"]

            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                             1433, 1521, 3306, 3389, 5432, 5900, 6379, 7001, 8000, 8080, 8443,
                             8888, 9090, 9200, 9300, 27017]
            open_ports = []
            for p in ports_to_scan:
                ret = port_single_scan(ip, p)
                if ret["open"]:
                    service = service_port_map.get(p, "unknown")
                    ret["service"] = service
                    open_ports.append(ret)

            web_info = {}
            web_ports = [80, 443, 8080, 8443, 8000, 8888, 9090, 7001, 7002]
            for port in web_ports:
                if not any(p["port"] == port for p in open_ports):
                    continue
                protocol = "https" if port in [443, 8443] else "http"
                url = f"{protocol}://{sub_domain}:{port}" if port not in [80, 443] else f"{protocol}://{sub_domain}"
                try:
                    r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                    title = ""
                    meta = ""
                    title_match = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        title = title_match.group(1).strip()
                    meta_match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', r.text, re.IGNORECASE)
                    if meta_match:
                        meta = meta_match.group(1).strip()
                    server = r.headers.get("Server", "")
                    web_info[url] = {
                        "status": r.status_code,
                        "server": server,
                        "title": title,
                        "meta_description": meta,
                        "headers": dict(r.headers)
                    }
                    if r.status_code in [200, 403, 401]:
                        dirs_found = []
                        for d in dir_list:
                            try:
                                full_url = url + d
                                resp = requests.get(full_url, timeout=2, verify=False)
                                if resp.status_code in [200, 403, 401, 301, 302]:
                                    dirs_found.append({"path": d, "status": resp.status_code})
                            except:
                                continue
                        web_info[url]["directories"] = dirs_found
                    else:
                        web_info[url]["directories"] = []
                except Exception as e:
                    logger.debug(f"[AppScan] 访问 {url} 失败: {e}")

            asset_entry = {
                "subdomain": sub_domain,
                "ip": ip,
                "open_ports": open_ports,
                "web_services": web_info
            }
            all_assets.append(asset_entry)

            if open_ports:
                asset = Asset.get_or_none(Asset.ip == ip, Asset.domain == sub_domain)
                if not asset:
                    Asset.create(
                        asset_id=generate_uuid(),
                        ip=ip,
                        domain=sub_domain,
                        asset_name=f"资产_{sub_domain}",
                        asset_type="web" if web_info else "host",
                        tag="应用测绘",
                        port_info=json.dumps(open_ports, ensure_ascii=False),
                        service_finger=json.dumps(web_info, ensure_ascii=False)
                    )
                else:
                    asset.port_info = json.dumps(open_ports, ensure_ascii=False)
                    asset.service_finger = json.dumps(web_info, ensure_ascii=False)
                    asset.save()

        final_result = {
            "domain": domain,
            "main_ip": main_ip,
            "total_subdomains": len(subdomains_found),
            "total_assets_with_ports": len([a for a in all_assets if a["open_ports"]]),
            "assets": all_assets
        }

        save_json_report(final_result, f"app_scan_{task_id}")
        write_audit_log("应用资产测绘", domain, f"发现子域{len(subdomains_found)}个，有端口资产{len([a for a in all_assets if a['open_ports']])}个", "完成")
        TaskRecord.update(status="finished", result=json.dumps(final_result), finish_time=datetime.datetime.now()).where(TaskRecord.task_id == task_id).execute()
        logger.info(f"[AppScan] 任务完成: {task_id}")

    except Exception as e:
        TaskRecord.update(status="error", result=str(e)).where(TaskRecord.task_id == task_id).execute()
        logging.error(f"[AppScan] 任务失败: {task_id}, 错误: {e}")

# ========================== 修改部分开始 ==========================
def ssh_exec(ip, port, user, pwd, cmd, timeout=10):
    """
    增强版 SSH 连接执行命令
    自动处理交互式命令（如 top）转换为批处理模式
    """
    # ===== 1. 预处理命令：如果是 top，自动添加批处理参数 =====
    cmd_stripped = cmd.strip()
    if cmd_stripped.startswith('top'):
        # 检查是否已有 -b 或 -n 参数
        if not any(opt in cmd_stripped for opt in ['-b', '-n']):
            cmd = 'top -b -n 1'
            logging.info(f"[SSH] 将 top 命令转换为批处理模式: {cmd}")

    # ===== 2. 检测端口是否开放 =====
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.close()
    except Exception as e:
        return {"success": False, "msg": f"端口 {port} 不可达或连接超时: {str(e)}"}

    # ===== 3. SSH 连接 =====
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            ip,
            port=port,
            username=user,
            password=pwd,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
            compress=False
        )
        # 执行命令
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout, get_pty=False)
        out = stdout.read().decode("utf8", errors="ignore")
        err = stderr.read().decode("utf8", errors="ignore")
        ssh.close()
        return {"success": True, "output": out, "error": err}
    except paramiko.AuthenticationException:
        return {"success": False, "msg": "认证失败：用户名或密码错误"}
    except paramiko.SSHException as e:
        return {"success": False, "msg": f"SSH 协议错误: {str(e)}"}
    except socket.timeout:
        return {"success": False, "msg": f"SSH 连接超时（{timeout}秒）"}
    except Exception as e:
        return {"success": False, "msg": f"未知异常: {str(e)}"}
# ========================== 修改部分结束 ==========================

def async_config_check(task_id, ip, port, user, pwd, os_type):
    """等保配置核查"""
    try:
        items = []
        if os_type == "linux":
            items = [
                {"name": "SSH弱密码允许", "cmd": "grep PermitEmptyPasswords /etc/ssh/sshd_config"},
                {"name": "root远程登录", "cmd": "grep PermitRootLogin /etc/ssh/sshd_config"},
                {"name": "密码认证开启", "cmd": "grep PasswordAuthentication /etc/ssh/sshd_config"},
                {"name": "防火墙状态", "cmd": "systemctl status firewalld || ufw status"},
                {"name": "登录审计日志", "cmd": "cat /var/log/secure | head -10"},
            ]
        else:
            items = [
                {"name": "远程桌面开启", "cmd": "qwinsta"},
                {"name": "管理员弱口令策略", "cmd": "net accounts"},
                {"name": "防火墙配置", "cmd": "netsh advfirewall show allprofiles"},
            ]
        result = []
        for item in items:
            ret = ssh_exec(ip, port, user, pwd, item["cmd"])
            result.append({"check_name": item["name"], "cmd": item["cmd"], "scan_result": ret})
        save_json_report(result, f"config_check_{task_id}")
        write_audit_log(f"{os_type}配置核查", ip, f"完成{len(result)}项等保检查", "完成")
        TaskRecord.update(status="finished", result=json.dumps(result), finish_time=datetime.datetime.now()).where(TaskRecord.task_id == task_id).execute()
    except Exception as e:
        TaskRecord.update(status="error", result=str(e)).where(TaskRecord.task_id == task_id).execute()

def async_nuclei_scan(task_id, target_list):
    """Nuclei扫描 - 使用临时文件捕获结果"""
    try:
        NUCLEI_PATH = r"E:\nuclei_3.9.0_windows_amd64\nuclei.exe"
        if not os.path.exists(NUCLEI_PATH):
            raise Exception(f"nuclei 可执行文件不存在: {NUCLEI_PATH}")

        template_path = NUCLEI_TEMPLATE_PATH
        use_template = False
        if template_path and os.path.exists(template_path):
            try:
                if os.path.isdir(template_path) and os.listdir(template_path):
                    use_template = True
                    logging.info(f"[Nuclei] 使用自定义模板目录: {template_path}")
                else:
                    logging.warning(f"[Nuclei] 模板目录为空，将使用内置默认模板")
            except Exception as e:
                logging.warning(f"[Nuclei] 无法读取模板目录: {e}，将使用内置默认模板")
        else:
            logging.warning(f"[Nuclei] 模板目录不存在，将使用内置默认模板")

        report_data = []

        for target in target_list:
            target = target.strip()
            if not target:
                continue

            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json', encoding='utf-8') as tmp:
                output_file = tmp.name

            try:
                if use_template:
                    cmd = [NUCLEI_PATH, "-u", target, "-t", template_path, "-json", "-o", output_file]
                else:
                    cmd = [NUCLEI_PATH, "-u", target, "-json", "-o", output_file]

                logging.info(f"[Nuclei] 执行命令: {' '.join(cmd)}")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    encoding='utf-8',
                    errors='ignore'
                )

                if result.returncode != 0 and result.returncode != 2:
                    error_msg = result.stderr.strip() if result.stderr else "无错误信息"
                    raise Exception(f"nuclei 执行失败 (返回码 {result.returncode}): {error_msg}")

                if result.stderr:
                    logging.warning(f"[Nuclei] stderr: {result.stderr.strip()}")

                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                logging.info(f"[Nuclei] 临时文件内容（前200字符）: {content[:200]}")

                lines = content.splitlines()
                logging.info(f"[Nuclei] 临时文件行数: {len(lines)}")

                json_count = 0
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        vuln_data = json.loads(line)
                    except json.JSONDecodeError:
                        if line.startswith('{') and line.endswith('}'):
                            try:
                                vuln_data = json.loads(line)
                            except:
                                continue
                        else:
                            continue
                    json_count += 1
                    report_data.append(vuln_data)

                    severity = vuln_data.get("info", {}).get("severity", "info")
                    netloc = urlparse(target).netloc
                    ip = netloc.split(":")[0] if ":" in netloc else netloc
                    asset = Asset.select().where(Asset.ip == ip).first()
                    if asset:
                        Vulnerability.create(
                            vuln_id=generate_uuid(),
                            asset=asset.asset_id,
                            vuln_name=vuln_data.get("info", {}).get("name", "未知漏洞"),
                            severity=severity,
                            poc_source="nuclei模板",
                            detail=json.dumps(vuln_data, ensure_ascii=False)
                        )

                logging.info(f"[Nuclei] 解析到 {json_count} 条 JSON 结果")

            finally:
                if os.path.exists(output_file):
                    os.unlink(output_file)

        save_json_report(report_data, f"nuclei_{task_id}")
        write_audit_log("Nuclei漏洞扫描", str(target_list), f"扫描发现漏洞{len(report_data)}条", "完成")
        TaskRecord.update(
            status="finished",
            result=json.dumps(report_data),
            finish_time=datetime.datetime.now()
        ).where(TaskRecord.task_id == task_id).execute()

    except subprocess.TimeoutExpired:
        TaskRecord.update(status="error", result="扫描超时（600秒）").where(TaskRecord.task_id == task_id).execute()
        logging.error("[Nuclei] 扫描超时")
    except Exception as e:
        TaskRecord.update(status="error", result=str(e)).where(TaskRecord.task_id == task_id).execute()
        logging.error(f"[Nuclei] 扫描失败: {e}")

def async_weakpass(task_id, ip, proto):
    """弱口令爆破"""
    try:
        proto_map = {"ssh": 22, "mysql": 3306, "ftp": 21, "telnet": 23, "rdp": 3389, "pop3": 110}
        port = proto_map.get(proto)
        if not port:
            raise Exception(f"不支持的协议: {proto}")
        user_dict = ["root", "admin", "test", "user", "guest"]
        pass_dict = ["123456", "root", "admin", "123123", "password", "123321"]
        hit = []
        for u in user_dict:
            for p in pass_dict:
                if proto == "ssh":
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        ssh.connect(ip, port, u, p, timeout=2, allow_agent=False, look_for_keys=False)
                        ssh.close()
                        hit.append({"proto": proto, "user": u, "pass": p, "port": port})
                        asset = Asset.select().where(Asset.ip == ip).first()
                        if asset:
                            AssetAccount.create(asset=asset.asset_id, protocol=proto, username=u, password=p, port=port)
                    except:
                        pass
        write_audit_log(f"{proto}弱口令爆破", ip, f"命中弱口令{len(hit)}组", "完成")
        TaskRecord.update(status="finished", result=json.dumps(hit), finish_time=datetime.datetime.now()).where(TaskRecord.task_id == task_id).execute()
    except Exception as e:
        TaskRecord.update(status="error", result=str(e)).where(TaskRecord.task_id == task_id).execute()