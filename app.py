from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import json
import datetime
import threading
import os
import paramiko
import time
import socket
import logging
import asyncio
import websockets
from functools import wraps
from models import Asset, Vulnerability, AssetAccount, AuditLog, BatchTask, TaskRecord, User
from utils import write_audit_log, generate_uuid, save_json_report
from tasks import async_host_scan, async_app_scan, async_config_check, async_nuclei_scan, async_weakpass, ssh_exec
from config import LOG_PATH, REPORT_PATH

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.secret_key = app.config['SECRET_KEY']  # 用于session

BATCH_RESULT_PATH = os.path.join(REPORT_PATH, 'batch_results')
os.makedirs(BATCH_RESULT_PATH, exist_ok=True)

# 存储 SSH 会话
ssh_sessions = {}

# ---------- 登录装饰器 ----------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# ---------- 创建默认管理员账号 ----------
def create_default_admin():
    admin = User.get_or_none(User.username == 'admin')
    if not admin:
        admin = User(username='admin')
        admin.set_password('123456')  # 默认密码，请及时修改
        admin.save()
        logger.info("默认管理员账号已创建: admin / 123456")

# ==================== 页面路由 ====================
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.get_or_none(User.username == username)
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='用户名或密码错误')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if new_password != confirm_password:
            return render_template('change_password.html', error='两次输入的新密码不一致')
        user = User.get_by_id(session['user_id'])
        if not user.check_password(old_password):
            return render_template('change_password.html', error='当前密码错误')
        user.set_password(new_password)
        user.save()
        return render_template('change_password.html', success='密码修改成功')
    return render_template('change_password.html')

@app.route('/')
@login_required
def index():
    total_assets = Asset.select().count()
    vuln_stat = {
        'high': Vulnerability.select().where(Vulnerability.severity=='high').count(),
        'mid': Vulnerability.select().where(Vulnerability.severity=='mid').count(),
        'low': Vulnerability.select().where(Vulnerability.severity=='low').count(),
        'unfixed': Vulnerability.select().where(Vulnerability.status=='found').count(),
        'fixed': Vulnerability.select().where(Vulnerability.status=='fix').count()
    }
    return render_template('index.html', total_assets=total_assets, vuln_stat=vuln_stat)

@app.route('/assets')
@login_required
def assets_page():
    return render_template('assets.html')

@app.route('/vulns')
@login_required
def vulns_page():
    return render_template('vulns.html')

@app.route('/scan')
@login_required
def scan_page():
    return render_template('scan.html')

@app.route('/config_check')
@login_required
def config_check_page():
    return render_template('config_check.html')

@app.route('/nuclei')
@login_required
def nuclei_page():
    return render_template('nuclei.html')

@app.route('/weakpass')
@login_required
def weakpass_page():
    return render_template('weakpass.html')

@app.route('/batch')
@login_required
def batch_page():
    return render_template('batch_ops.html')

@app.route('/logs')
@login_required
def logs_page():
    return render_template('logs.html')

@app.route('/terminal/<asset_id>')
@login_required
def terminal_page(asset_id):
    return render_template('terminal.html', asset_id=asset_id)

# ==================== RESTful API（全部添加登录保护） ====================
@app.route('/api/assets', methods=['GET'])
@login_required
def get_assets():
    assets = Asset.select().dicts()
    return jsonify(list(assets))

@app.route('/api/assets', methods=['POST'])
@login_required
def add_asset():
    data = request.json
    aid = generate_uuid()
    Asset.create(
        asset_id=aid,
        ip=data['ip'],
        domain=data.get('domain',''),
        asset_name=data['name'],
        asset_type=data['type'],
        tag=data.get('tag','')
    )
    write_audit_log("资产新增", data['ip'], f"新增资产{data['name']}", "成功")
    return jsonify({'status':'ok', 'asset_id':aid})

@app.route('/api/assets/<asset_id>', methods=['PUT'])
@login_required
def update_asset(asset_id):
    data = request.json
    asset = Asset.get_by_id(asset_id)
    for key in ['ip','domain','asset_name','asset_type','tag','status']:
        if key in data:
            setattr(asset, key, data[key])
    asset.update_time = datetime.datetime.now()
    asset.save()
    write_audit_log("资产更新", asset_id, "更新资产信息", "成功")
    return jsonify({'status':'ok'})

@app.route('/api/assets/<asset_id>', methods=['DELETE'])
@login_required
def delete_asset(asset_id):
    asset = Asset.get_by_id(asset_id)
    asset.delete_instance(recursive=True)
    write_audit_log("资产删除", asset_id, "删除资产", "成功")
    return jsonify({'status':'ok'})

@app.route('/api/accounts', methods=['POST'])
@login_required
def add_account():
    data = request.json
    asset_id = data.get('asset_id')
    protocol = data.get('protocol', 'ssh')
    username = data.get('username')
    password = data.get('password')
    port = int(data.get('port', 22))
    if not asset_id or not username:
        return jsonify({'error': 'asset_id and username required'}), 400
    asset = Asset.get_or_none(Asset.asset_id == asset_id)
    if not asset:
        return jsonify({'error': 'asset not found'}), 404
    existing = AssetAccount.get_or_none(asset=asset_id, protocol=protocol, username=username)
    if existing:
        return jsonify({'error': 'account already exists'}), 400
    acc = AssetAccount.create(
        asset=asset_id,
        protocol=protocol,
        username=username,
        password=password,
        port=port
    )
    write_audit_log("添加账号", asset_id, f"{protocol}账号 {username} 添加", "成功")
    return jsonify({'status': 'ok', 'id': acc.id})

@app.route('/api/accounts/<int:acc_id>', methods=['DELETE'])
@login_required
def delete_account(acc_id):
    acc = AssetAccount.get_or_none(AssetAccount.id == acc_id)
    if not acc:
        return jsonify({'error': 'not found'}), 404
    acc.delete_instance()
    write_audit_log("删除账号", str(acc_id), "删除账号", "成功")
    return jsonify({'status': 'ok'})

@app.route('/api/accounts/<asset_id>', methods=['GET'])
@login_required
def get_accounts(asset_id):
    accounts = AssetAccount.select().where(AssetAccount.asset == asset_id).dicts()
    return jsonify(list(accounts))

@app.route('/api/asset/test/<asset_id>', methods=['GET'])
@login_required
def test_asset_ssh(asset_id):
    asset = Asset.get_or_none(Asset.asset_id == asset_id)
    if not asset:
        return jsonify({'error': 'asset not found'}), 404
    account = AssetAccount.select().where(AssetAccount.asset == asset_id, AssetAccount.protocol == 'ssh').first()
    if not account:
        return jsonify({'error': '该资产未配置 SSH 账号'}), 400
    result = ssh_exec(asset.ip, account.port, account.username, account.password, 'echo "SSKit test successful"')
    return jsonify({
        'ip': asset.ip,
        'username': account.username,
        'result': result
    })

@app.route('/api/asset/exec/<asset_id>', methods=['POST'])
@login_required
def asset_exec(asset_id):
    data = request.json
    cmd = data.get('cmd')
    if not cmd:
        return jsonify({'error': '命令不能为空'}), 400
    asset = Asset.get_or_none(Asset.asset_id == asset_id)
    if not asset:
        return jsonify({'error': '资产不存在'}), 404
    account = AssetAccount.select().where(AssetAccount.asset == asset_id, AssetAccount.protocol == 'ssh').first()
    if not account:
        return jsonify({'error': '该资产未配置 SSH 账号'}), 400
    result = ssh_exec(asset.ip, account.port, account.username, account.password, cmd)
    write_audit_log("远程执行命令", asset.ip, f"执行命令: {cmd}", "成功" if result.get('success') else "失败")
    return jsonify({
        'ip': asset.ip,
        'username': account.username,
        'result': result
    })

@app.route('/api/vulns', methods=['GET'])
@login_required
def get_vulns():
    vulns = Vulnerability.select().dicts()
    return jsonify(list(vulns))

@app.route('/api/vulns', methods=['POST'])
@login_required
def add_vuln():
    data = request.json
    vid = generate_uuid()
    asset = Asset.get_by_id(data['asset_id'])
    Vulnerability.create(
        vuln_id=vid,
        asset=asset.asset_id,
        vuln_name=data['vuln_name'],
        severity=data['severity'],
        poc_source=data.get('poc_source','手动录入'),
        detail=data.get('detail','')
    )
    write_audit_log("漏洞录入", data['asset_id'], f"新增漏洞{data['vuln_name']}", "成功")
    return jsonify({'status':'ok', 'vuln_id':vid})

@app.route('/api/vulns/<vuln_id>/fix', methods=['POST'])
@login_required
def fix_vuln(vuln_id):
    vuln = Vulnerability.get_by_id(vuln_id)
    vuln.status = 'fix'
    vuln.save()
    write_audit_log("漏洞修复标记", vuln_id, "标记漏洞已修复", "成功")
    return jsonify({'status':'ok'})

@app.route('/api/vulns/<vuln_id>/verify', methods=['POST'])
@login_required
def verify_vuln(vuln_id):
    vuln = Vulnerability.get_by_id(vuln_id)
    vuln.status = 'verify'
    vuln.save()
    write_audit_log("漏洞复测验证", vuln_id, "漏洞复测无风险", "完成")
    return jsonify({'status':'ok'})

@app.route('/api/tasks', methods=['POST'])
@login_required
def create_task():
    data = request.json
    task_type = data['type']
    target = data['target']
    task_id = generate_uuid()
    TaskRecord.create(task_id=task_id, task_type=task_type, target=target, status='running')
    
    if task_type == 'host_scan':
        t = threading.Thread(target=async_host_scan, args=(task_id, target))
    elif task_type == 'app_scan':
        t = threading.Thread(target=async_app_scan, args=(task_id, target))
    elif task_type == 'config_check':
        port = int(data.get('port', 22))
        user = data['user']
        pwd = data['pwd']
        os_type = data.get('os_type', 'linux')
        t = threading.Thread(target=async_config_check, args=(task_id, target, port, user, pwd, os_type))
    elif task_type == 'nuclei':
        targets = target.split(',')
        t = threading.Thread(target=async_nuclei_scan, args=(task_id, targets))
    elif task_type == 'weakpass':
        proto = data.get('proto', 'ssh')
        t = threading.Thread(target=async_weakpass, args=(task_id, target, proto))
    else:
        return jsonify({'error':'unknown task type'}), 400
    t.daemon = True
    t.start()
    return jsonify({'task_id':task_id})

@app.route('/api/tasks/<task_id>', methods=['GET'])
@login_required
def get_task_status(task_id):
    task = TaskRecord.get_or_none(TaskRecord.task_id == task_id)
    if not task:
        return jsonify({'error': 'not found'}), 404
    
    result_data = None
    if task.result:
        try:
            result_data = json.loads(task.result)
        except (json.JSONDecodeError, TypeError):
            result_data = task.result
    
    return jsonify({
        'status': task.status,
        'result': result_data,
        'create_time': task.create_time.strftime('%Y-%m-%d %H:%M:%S'),
        'finish_time': task.finish_time.strftime('%Y-%m-%d %H:%M:%S') if task.finish_time else None
    })

@app.route('/api/batch/cmd', methods=['POST'])
@login_required
def batch_cmd():
    data = request.json
    asset_ids_str = data['asset_ids']
    asset_ids = [x.strip() for x in asset_ids_str.split(',') if x.strip()]
    cmd = data['cmd']
    task_id = generate_uuid()
    
    BatchTask.create(
        task_id=task_id,
        task_type='batch_cmd',
        target_asset_list=json.dumps(asset_ids),
        cmd_content=cmd
    )
    
    def run():
        results = []
        success_count = 0
        for aid in asset_ids:
            asset = Asset.get_or_none(Asset.asset_id == aid)
            if not asset:
                results.append({'asset_id': aid, 'ip': '未知', 'success': False, 'msg': '资产不存在'})
                continue
            account = AssetAccount.select().where(AssetAccount.asset == aid, AssetAccount.protocol == 'ssh').first()
            if not account:
                results.append({'asset_id': aid, 'ip': asset.ip, 'success': False, 'msg': '未配置 SSH 账号'})
                continue
            ret = ssh_exec(asset.ip, account.port, account.username, account.password, cmd)
            if ret.get('success'):
                success_count += 1
                results.append({
                    'asset_id': aid,
                    'ip': asset.ip,
                    'success': True,
                    'output': ret.get('output', ''),
                    'error': ret.get('error', '')
                })
            else:
                results.append({
                    'asset_id': aid,
                    'ip': asset.ip,
                    'success': False,
                    'msg': ret.get('msg', '未知错误')
                })
        result_file = os.path.join(BATCH_RESULT_PATH, f"{task_id}.json")
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        BatchTask.update(status='finish').where(BatchTask.task_id == task_id).execute()
        write_audit_log("批量命令执行", str(asset_ids), f"成功{success_count}台主机执行命令", "完成")
    
    threading.Thread(target=run, daemon=True).start()
    return jsonify({'task_id': task_id})

@app.route('/api/batch/result/<task_id>', methods=['GET'])
@login_required
def get_batch_result(task_id):
    result_file = os.path.join(BATCH_RESULT_PATH, f"{task_id}.json")
    if not os.path.exists(result_file):
        task = BatchTask.get_or_none(BatchTask.task_id == task_id)
        if task and task.status == 'finish':
            return jsonify({'error': '结果文件不存在'}), 404
        return jsonify({'status': 'running'})
    with open(result_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return jsonify({'status': 'finished', 'results': data})

@app.route('/api/batch/upload', methods=['POST'])
@login_required
def batch_upload():
    data = request.json
    asset_ids_str = data['asset_ids']
    asset_ids = [x.strip() for x in asset_ids_str.split(',') if x.strip()]
    local_file = data['local_file']
    remote_path = data['remote_path']
    task_id = generate_uuid()
    
    BatchTask.create(
        task_id=task_id,
        task_type='file_dist',
        target_asset_list=json.dumps(asset_ids),
        file_path=f"{local_file}->{remote_path}"
    )
    
    def run():
        results = []
        success_count = 0
        import paramiko
        for aid in asset_ids:
            asset = Asset.get_or_none(Asset.asset_id == aid)
            if not asset:
                results.append({'asset_id': aid, 'ip': '未知', 'success': False, 'msg': '资产不存在'})
                continue
            account = AssetAccount.select().where(AssetAccount.asset == aid, AssetAccount.protocol == 'ssh').first()
            if not account:
                results.append({'asset_id': aid, 'ip': asset.ip, 'success': False, 'msg': '未配置 SSH 账号'})
                continue
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(asset.ip, account.port, account.username, account.password, timeout=10)
                sftp = ssh.open_sftp()
                sftp.put(local_file, remote_path)
                sftp.close()
                ssh.close()
                success_count += 1
                results.append({'asset_id': aid, 'ip': asset.ip, 'success': True, 'msg': '上传成功'})
            except Exception as e:
                results.append({'asset_id': aid, 'ip': asset.ip, 'success': False, 'msg': str(e)})
        result_file = os.path.join(BATCH_RESULT_PATH, f"{task_id}.json")
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        BatchTask.update(status='finish').where(BatchTask.task_id == task_id).execute()
        write_audit_log("批量文件分发", str(asset_ids), f"本地{local_file}推送至{remote_path}，成功{success_count}", "完成")
    
    threading.Thread(target=run, daemon=True).start()
    return jsonify({'task_id': task_id})

@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    limit = int(request.args.get('limit', 100))
    logs = AuditLog.select().order_by(AuditLog.op_time.desc()).limit(limit).dicts()
    return jsonify(list(logs))

# ==================== WebSocket 处理函数（最终修复） ====================
async def websocket_handler(websocket):
    client_id = id(websocket)
    logger.info(f"[WebSocket] 新连接: {client_id}")
    
    loop = asyncio.get_running_loop()
    
    try:
        message = await websocket.recv()
        data = json.loads(message)
        
        if data.get('type') == 'ssh_connect':
            session_id = data.get('session_id')
            host = data.get('host')
            port = int(data.get('port', 22))
            username = data.get('username')
            password = data.get('password')
            
            logger.info(f"[SSH] 连接请求: {host}:{port} 用户 {username}")
            
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, port=port, username=username, password=password, timeout=10)
                ssh.get_transport().set_keepalive(30)
                logger.info(f"[SSH] 连接成功 {host}:{port}")
                
                channel = ssh.invoke_shell(term='xterm', width=120, height=30)
                channel.settimeout(0.5)
                
                ssh_sessions[session_id] = {
                    'ssh': ssh,
                    'channel': channel,
                    'websocket': websocket,
                    'client_id': client_id,
                    'alive': True,
                    'loop': loop
                }
                
                await websocket.send(json.dumps({'type': 'ssh_connected', 'session_id': session_id}))
                channel.send('\n\n')
                
                def read_output():
                    while session_id in ssh_sessions and ssh_sessions[session_id]['alive']:
                        try:
                            if channel.recv_ready():
                                data = channel.recv(4096).decode('utf-8', errors='ignore')
                                if data:
                                    asyncio.run_coroutine_threadsafe(
                                        websocket.send(json.dumps({'type': 'ssh_output', 'data': data, 'session_id': session_id})),
                                        loop
                                    )
                            else:
                                time.sleep(0.05)
                        except socket.timeout:
                            continue
                        except Exception as e:
                            logger.error(f"[SSH] 读取异常: {e}")
                            break
                    if session_id in ssh_sessions:
                        del ssh_sessions[session_id]
                    logger.info(f"[SSH] 会话清理: {session_id}")
                
                thread = threading.Thread(target=read_output, daemon=True)
                thread.start()
                
                async for message in websocket:
                    try:
                        msg = json.loads(message)
                        if msg.get('type') == 'ssh_input':
                            input_data = msg.get('data', '')
                            if session_id in ssh_sessions:
                                channel = ssh_sessions[session_id]['channel']
                                if input_data == '\r':
                                    channel.send('\n')
                                else:
                                    channel.send(input_data)
                    except json.JSONDecodeError:
                        pass
                    
            except paramiko.AuthenticationException:
                await websocket.send(json.dumps({'type': 'ssh_error', 'error': '认证失败：用户名或密码错误'}))
            except paramiko.SSHException as e:
                await websocket.send(json.dumps({'type': 'ssh_error', 'error': f'SSH 连接失败: {str(e)}'}))
            except Exception as e:
                await websocket.send(json.dumps({'type': 'ssh_error', 'error': f'连接失败: {str(e)}'}))
                
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"[WebSocket] 连接关闭: {client_id}")
    except Exception as e:
        logger.error(f"[WebSocket] 异常: {e}")
    finally:
        for sid, session in list(ssh_sessions.items()):
            if session['client_id'] == client_id:
                session['alive'] = False
                session['ssh'].close()
                del ssh_sessions[sid]
                logger.info(f"[SSH] 会话清理: {sid}")

# ==================== 启动 WebSocket 服务器 ====================
async def start_websocket_server():
    async with websockets.serve(websocket_handler, "0.0.0.0", 8765):
        logger.info("WebSocket 服务器启动在 ws://0.0.0.0:8765")
        await asyncio.Future()

# ==================== 启动 Flask（子线程） ====================
def run_flask():
    app.run(debug=False, host='0.0.0.0', port=5000)

# ==================== 入口 ====================
if __name__ == '__main__':
    # 创建默认管理员
    create_default_admin()
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    logger.info("Web UI 启动中: http://localhost:5000")
    try:
        asyncio.run(start_websocket_server())
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("服务已停止")