from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from urllib.parse import urlparse, urljoin
from datetime import timedelta, datetime
import os
import random
from flask_socketio import SocketIO, send, emit
import logging

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# 初始化 Flask 应用
app = Flask(__name__)

# 配置
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key'
base_dir = os.path.abspath(os.path.dirname(__file__))
instance_dir = os.path.join(base_dir, 'instance')
if not os.path.exists(instance_dir):
    os.makedirs(instance_dir)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_dir, "users.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(days=7)

# 初始化数据库
db = SQLAlchemy(app)
# 初始化 SocketIO
socketio = SocketIO(app, async_mode='eventlet', logger=True, engineio_logger=True)

# 在线用户集合
online_users = set()

# 数据模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    chat_count = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 表单类
class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('邮箱', validators=[DataRequired(), Email()])
    password = PasswordField('密码', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('确认密码', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('注册')

class LoginForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired(), Email()])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')

# 数据库表初始化
try:
    with app.app_context():
        db.create_all()
except Exception as e:
    logger.error(f"数据库初始化失败: {e}")
    raise

# 安全跳转校验
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# 登录保护装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录。', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# AI 聊天接口（模拟）
def get_ai_response(message):
    try:
        responses = [
            "哈哈，这个话题有意思！说说看，你还有啥想法？",
            "嗯，我觉得你说得有点道理，但可以再展开讲讲吗？",
            "哇，这个问题好有创意！我得想想…你的灵感哪来的？"
        ]
        return random.choice(responses)
    except:
        return "哎呀，AI 小助手有点懵，请再说一遍？"

# 路由视图
@app.route('/')
def home():
    return render_template('home.html', current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('该邮箱已被注册，请使用其他邮箱。', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=form.username.data).first():
            flash('该用户名已被使用，请选择其他用户名。', 'danger')
            return redirect(url_for('register'))
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('注册成功！请登录。', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            flash('登录成功！', 'success')
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('登录失败，请检查邮箱和密码。', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', 
                         username=session['username'], 
                         chat_count=user.chat_count,
                         online_count=len(online_users))

@app.route('/logout')
def logout():
    if 'username' in session:
        online_users.discard(session['username'])
        socketio.emit('update_users', {'users': list(online_users), 'count': len(online_users)}, broadcast=True)
    session.clear()
    flash('您已成功退出登录。', 'info')
    return redirect(url_for('home'))

@app.route('/chatroom')
@login_required
def chatroom():
    return render_template('chatroom.html', username=session['username'])

# SocketIO 事件处理
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        logger.debug(f"用户 {session['username']} 连接")
        online_users.add(session['username'])
        socketio.emit('update_users', {'users': list(online_users), 'count': len(online_users)}, broadcast=True)
    else:
        logger.warning("连接时无用户名，忽略")

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        logger.debug(f"用户 {session['username']} 断开连接")
        online_users.discard(session['username'])
        socketio.emit('update_users', {'users': list(online_users), 'count': len(online_users)}, broadcast=True)

@socketio.on('message')
def handle_message(message):
    if 'username' not in session:
        logger.warning("收到消息但无用户名，忽略")
        return
    username = session.get('username')
    user = User.query.get(session['user_id'])
    user.chat_count += 1
    db.session.commit()
    
    full_message = f'{username}说: {message}'
    logger.debug(f"广播消息: {full_message}")
    socketio.emit('message', full_message, broadcast=True)
    
    if message.startswith('@AI'):
        ai_response = get_ai_response(message[3:].strip())
        ai_message = f'AI助手说: {ai_response}'
        logger.debug(f"广播AI消息: {ai_message}")
        socketio.emit('message', ai_message, broadcast=True)

@socketio.on('login')
def handle_login(data):
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        session['user_id'] = user.id
        session['username'] = user.username
        logger.debug(f"用户 {user.username} 登录成功")
        socketio.emit('login_success')
    else:
        logger.warning("登录失败")
        socketio.emit('login_failure')

@socketio.on('register')
def handle_register(data):
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if User.query.filter_by(email=email).first():
        logger.warning("注册失败：邮箱已存在")
        socketio.emit('register_failure')
        return
    if User.query.filter_by(username=username).first():
        logger.warning("注册失败：用户名已存在")
        socketio.emit('register_failure')
        return
    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    logger.debug(f"用户 {username} 注册成功")
    socketio.emit('register_success')

# 启动应用
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', debug=True)