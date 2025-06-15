# app.py
import base64
import os
from datetime import datetime
from datetime import timedelta
from functools import wraps
from io import BytesIO
from flask import g, render_template_string
import qrcode
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, abort
from flask import flash
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from passlib.hash import pbkdf2_sha256
from werkzeug.utils import secure_filename
from wtforms import BooleanField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.fields.numeric import IntegerField
from wtforms.validators import DataRequired, NumberRange
from flask_wtf.csrf import CSRFProtect
import sys
from pathlib import Path
from flask import Flask

if getattr(sys, 'frozen', False):
    # 打包后模式
    base_path = Path(sys._MEIPASS)
    template_folder = base_path / 'templates'
    static_folder = base_path / 'static'
    app = Flask(__name__,
               template_folder=str(template_folder),
               static_folder=str(static_folder))
else:
    # 开发模式
    app = Flask(__name__)

app.config['INITIALIZED'] = False
app.config['SECRET_KEY'] = 'nj96khu3'  # 必须设置密钥
csrf = CSRFProtect(app)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
db = SQLAlchemy(app)
class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)
with app.app_context():
    db.create_all()  # 确保这行代码在所有模型定义之后
    print("已创建数据库表：", db.metadata.tables.keys())  # 调试输出






class RegisterForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])
    is_admin = BooleanField('管理员权限')
    submit = SubmitField('创建用户')
# 新的数据库模型
class SystemStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    initialized = db.Column(db.Boolean, default=False)


# 初始化默认配置（如果不存在）
with app.app_context():
    if not Config.query.filter_by(key='max_file_size').first():
        db.session.add(Config(key='max_file_size', value='16'))  # 默认16MB
    db.session.commit()




# 管理员专属装饰器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 检查登录状态
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))

        # 检查管理员权限
        if not session.get('is_admin'):
            abort(403)

        return f(*args, **kwargs)

    return decorated_function

# 初始化检查装饰器
def check_initialized(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        status = SystemStatus.query.first()
        # 处理首次运行时的空状态
        if not status or not status.initialized:
            return redirect(url_for('initial_setup'))
        return func(*args, **kwargs)
    return wrapper

# 添加新的表单类
class InitialSetupForm(FlaskForm):
    username = StringField('管理员账号', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])
    confirm_password = PasswordField('确认密码', validators=[DataRequired()])
    submit = SubmitField('初始化系统')



# 数据库模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), unique=True, nullable=False)



# 初始化数据库
with app.app_context():
    db.create_all()
    if not SystemStatus.query.first():
        db.session.add(SystemStatus(initialized=False))
    if not Config.query.filter_by(key='upload_folder').first():
        db.session.add(Config(key='upload_folder', value=app.config['UPLOAD_FOLDER']))
    if not Config.query.filter_by(key='blocked_extensions').first():
        db.session.add(Config(key='blocked_extensions', value='exe,php,sh'))

    db.session.commit()


# 表单类
class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')


class AdminSettingsForm(FlaskForm):
    upload_folder = StringField('存储目录')
    blocked_extensions = StringField('禁止的文件类型')
    ip_address = StringField('封禁IP地址')
    submit = SubmitField('保存设置')


class AdminSettingsForm(FlaskForm):
    upload_folder = StringField('存储目录')
    max_file_size = IntegerField('最大文件大小(MB)', validators=[
        DataRequired(),
        NumberRange(min=1, max=2048)  # 限制1MB-2GB
    ])
    blocked_extensions = StringField('禁止的文件类型')
    ip_address = StringField('封禁IP地址')
    submit = SubmitField('保存设置')


# 辅助函数
def get_config(key):
    return Config.query.filter_by(key=key).first().value


def is_banned(ip):
    return BannedIP.query.filter_by(ip_address=ip).first() is not None
@app.route('/test-csrf')
def test_csrf():
    return render_template_string('''
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button type="submit">Test</button>
        </form>
    ''')
# 初始化路由
@app.route('/initial-setup', methods=['GET', 'POST'])
def initial_setup():
    status = SystemStatus.query.first()
    if status and status.initialized:
        return redirect(url_for('index'))


    form = InitialSetupForm()

    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            flash('两次输入的密码不一致')
            return redirect(url_for('initial_setup'))

        hashed_pw = pbkdf2_sha256.hash(form.password.data)
        _admin = User(
            username=form.username.data,
            password_hash=hashed_pw,
            is_admin=True,

        )
        db.session.add(_admin)

        # 初始化系统状态
        if not SystemStatus.query.first():
            db.session.add(SystemStatus(initialized=True))
        else:
            SystemStatus.query.first().initialized = True

        db.session.commit()
        return redirect(url_for('login'))

    return render_template('initial_setup.html', form=form)


# 文件删除路由
@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    if not session.get('is_admin'):
        abort(403)

    upload_dir = get_config('upload_folder')
    target = os.path.join(upload_dir, secure_filename(filename))

    if os.path.exists(target):
        os.remove(target)
        return jsonify(success=True)
    return jsonify(error="文件不存在"), 404
@app.before_request
def check_ban():
    client_ip = request.remote_addr
    if is_banned(client_ip):
        abort(403)

# 自动权限检查功能
@app.before_request
def check_admin():
    with app.app_context():
        # 检查root用户权限
        root_user = db.session.get(User, 1)
        if root_user and not root_user.is_admin:
            root_user.is_admin = True
            db.session.commit()
            app.logger.info("Root用户已升级为管理员")

        # 确保至少存在一个管理员
        if not User.query.filter_by(is_admin=True).first():
            new_admin = User(
                username="admin",
                password_hash=pbkdf2_sha256.hash("TempPass123"),
                is_admin=True
            )
            db.session.add(new_admin)
            db.session.commit()
            app.logger.warning("已创建默认管理员账户")
# 主路由
@app.route('/')
def index():
    # 修改后代码
    current_user = None
    if session.get('user_id'):
        try:
            # 验证user_id为有效整数
            user_id = int(session['user_id'])
            current_user = db.session.get(User, user_id)
            # 处理用户不存在的情况
            if not current_user:
                session.clear()
        except (ValueError, TypeError):
            session.clear()

    upload_dir = get_config('upload_folder')
    files = []
    if os.path.exists(upload_dir):
        for f in os.listdir(upload_dir):
            path = os.path.join(upload_dir, f)
            if os.path.isfile(path):
                files.append({
                    'name': f,
                    'size': os.path.getsize(path),
                    'ctime': datetime.fromtimestamp(os.path.getctime(path))
                })

    return render_template('index.html',current_user=current_user,files=files,allowed_extensions=get_config('blocked_extensions'),max_file_size=int(get_config('max_file_size')),)


# 用户管理路由
@app.route('/admin/users', methods=['GET', 'POST'])
def manage_users():

    if not session.get('is_admin'):
        return redirect(url_for('login'))

    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = pbkdf2_sha256.hash(form.password.data)
        user = User(
            username=form.username.data,
            password_hash=hashed_pw,
            is_admin=form.is_admin.data
        )
        db.session.add(user)
        db.session.commit()
        flash('用户创建成功')

    users = User.query.all()
    return render_template('admin_users.html', form=form, users=users)


# 上传路由
@app.route('/upload', methods=['POST'])
def upload():


    if 'file' not in request.files:
        return jsonify(error="未选择文件"), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify(error="无效文件名"), 400

    # 获取动态配置
    max_size_mb = int(get_config('max_file_size'))
    max_size_bytes = max_size_mb * 1024 * 1024

    # 检查文件大小
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if file_size > max_size_bytes:
        return jsonify(error=f"文件大小超过限制（最大{max_size_mb}MB）"), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[-1].lower()

    if ext in get_config('blocked_extensions').split(','):
        return jsonify(error="禁止的文件类型"), 400

    upload_dir = get_config('upload_folder')
    os.makedirs(upload_dir, exist_ok=True)
    file.save(os.path.join(upload_dir, filename))

    # 生成二维码
    download_url = url_for('download', filename=filename, _external=True)
    qr = qrcode.make(download_url)
    buffered = BytesIO()
    qr.save(buffered)
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    return jsonify(
        success=True,
        filename=filename,
        download_url=download_url,
        qr_code=f"data:image/png;base64,{qr_base64}"
    )
# 下载路由
@app.route('/download/<filename>')
def download(filename):
    # 必须登录才能下载
    if 'user_id' not in session:
        abort(401)

    # 安全检查
    filename = secure_filename(filename)
    return send_from_directory(get_config('upload_folder'), filename, as_attachment=True)

# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 已登录用户直接跳转
    if 'user_id' in session:
        return redirect(url_for('index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = db.session.scalar(
            db.select(User).filter_by(username=form.username.data)
        )

        if user and pbkdf2_sha256.verify(form.password.data, user.password_hash):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(request.args.get('next') or url_for('index'))

        flash('无效的用户名或密码', 'error')

    return render_template('login.html', form=form)
# 持续性验证
@app.route('/check-session')
def check_session():
    return jsonify({
        'user_id': session.get('user_id'),
        'is_admin': session.get('is_admin'),
        'session_id': request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    })

# 管理员路由
@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():

    if not session.get('is_admin'):
        return redirect(url_for('login'))

    form = AdminSettingsForm()
    current_max = int(get_config('max_file_size'))

    if form.validate_on_submit():
        # 更新文件大小限制
        Config.query.filter_by(key='max_file_size').first().value = str(form.max_file_size.data)
        # 更新存储目录
        Config.query.filter_by(key='upload_folder').first().value = form.upload_folder.data
        # 更新禁止类型
        Config.query.filter_by(key='blocked_extensions').first().value = form.blocked_extensions.data
        # 封禁IP
        if form.ip_address.data:
            db.session.add(BannedIP(ip_address=form.ip_address.data))
        db.session.commit()

    form.upload_folder.data = get_config('upload_folder')
    form.blocked_extensions.data = get_config('blocked_extensions')
    form.max_file_size.data = current_max
    return render_template('admin.html',
                         form=form,
                         current_max_size=current_max,
                         banned_ips=BannedIP.query.all())
@app.before_request
def check_auth():
    g.user = None
    if session.get('user_id'):
        try:
            user_id = int(session['user_id'])
            user = db.session.get(User, user_id)
            if user:
                g.user = user
            else:
                session.clear()
        except (ValueError, TypeError):
            session.clear()
@app.before_request
def check_authentication():
    # 排除静态文件和初始化页面
    if request.path.startswith('/static') or request.path == '/initial-setup':
        return

    # 检查用户状态有效性
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if not user:
            session.clear()
# 登出路由
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    response = redirect(url_for('index'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    return response

@app.route('/unban/<int:id>')
def unban(id):
    if session.get('admin'):
        BannedIP.query.filter_by(id=id).delete()
        db.session.commit()
    return redirect(url_for('admin'))



@app.before_request
def check_initialization_status():
    # 允许访问初始化页面和静态资源
    excluded_paths = [url_for('initial_setup'), '/static/']
    if any(request.path.startswith(p) for p in excluded_paths):
        return

    status = SystemStatus.query.first()
    # 当系统未初始化时重定向
    if not status or not status.initialized:
        return redirect(url_for('initial_setup'))

# app.py 中添加以下代码

if __name__ == '__main__':
    app.run(debug=False)