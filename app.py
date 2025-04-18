from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from urllib.parse import urlparse, urljoin
from datetime import timedelta
import os
from flask_socketio import SocketIO, send

# 初始化 Flask 应用
app = Flask(__name__)

# 配置
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(days=7)

# 初始化数据库
db = SQLAlchemy(app)
# 初始化 SocketIO
socketio = SocketIO(app, async_mode='eventlet')

# 数据模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

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
with app.app_context():
    db.create_all()

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

# 路由视图
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # 检查邮箱是否存在
        if User.query.filter_by(email=form.email.data).first():
            flash('该邮箱已被注册，请使用其他邮箱。', 'danger')
            return redirect(url_for('register'))

        # 检查用户名是否存在
        if User.query.filter_by(username=form.username.data).first():
            flash('该用户名已被使用，请选择其他用户名。', 'danger')
            return redirect(url_for('register'))

        # 创建用户
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
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    flash('您已成功退出登录。', 'info')
    return redirect(url_for('home'))

@app.route('/chatroom')
@login_required
def chatroom():
    return render_template('chatroom.html', username=session['username'])

# SocketIO 事件处理
@socketio.on('login')
def handle_login(data):
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        session['user_id'] = user.id
        session['username'] = user.username
        socketio.emit('login_success')
    else:
        socketio.emit('login_failure')

@socketio.on('register')
def handle_register(data):
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if User.query.filter_by(email=email).first():
        socketio.emit('register_failure')
        return
    if User.query.filter_by(username=username).first():
        socketio.emit('register_failure')
        return
    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    socketio.emit('register_success')

@socketio.on('message')
def handle_message(message):
    username = session.get('username')
    full_message = f'{username}: {message}'
    send(full_message, broadcast=True)

# 启动应用
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0',debug=True)