import sys
import socketio
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox

# 初始化 SocketIO 客户端
sio = socketio.Client()

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('登录')
        layout = QVBoxLayout()

        self.email_label = QLabel('邮箱:')
        self.email_input = QLineEdit()
        self.password_label = QLabel('密码:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.login_button = QPushButton('登录')
        self.register_button = QPushButton('注册')

        layout.addWidget(self.email_label)
        layout.addWidget(self.email_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.register_button)

        self.login_button.clicked.connect(self.login)
        self.register_button.clicked.connect(self.register)

        self.setLayout(layout)

    def login(self):
        email = self.email_input.text()
        password = self.password_input.text()
        # 这里可以添加登录逻辑，例如发送登录请求到服务端
        sio.emit('login', {'email': email, 'password': password})

    def register(self):
        # 打开注册窗口
        self.register_window = RegisterWindow()
        self.register_window.show()
        self.close()

class RegisterWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('注册')
        layout = QVBoxLayout()

        self.username_label = QLabel('用户名:')
        self.username_input = QLineEdit()
        self.email_label = QLabel('邮箱:')
        self.email_input = QLineEdit()
        self.password_label = QLabel('密码:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_label = QLabel('确认密码:')
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.register_button = QPushButton('注册')

        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.email_label)
        layout.addWidget(self.email_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.confirm_password_label)
        layout.addWidget(self.confirm_password_input)
        layout.addWidget(self.register_button)

        self.register_button.clicked.connect(self.register)

        self.setLayout(layout)

    def register(self):
        username = self.username_input.text()
        email = self.email_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        if password != confirm_password:
            QMessageBox.warning(self, '警告', '两次输入的密码不一致，请重新输入。')
            return
        # 这里可以添加注册逻辑，例如发送注册请求到服务端
        sio.emit('register', {'username': username, 'email': email, 'password': password})

class ChatWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('聊天室')
        layout = QVBoxLayout()

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.message_input = QLineEdit()
        self.send_button = QPushButton('发送')

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)

        layout.addWidget(self.chat_display)
        layout.addLayout(input_layout)

        self.send_button.clicked.connect(self.send_message)
        sio.on('message', self.receive_message)

        self.setLayout(layout)

    def send_message(self):
        message = self.message_input.text()
        if message:
            sio.emit('message', message)
            self.message_input.clear()

    def receive_message(self, msg):
        self.chat_display.append(msg)

# SocketIO 事件处理
@sio.on('login_success')
def on_login_success():
    app.chat_window = ChatWindow()
    app.chat_window.show()
    app.login_window.close()

@sio.on('login_failure')
def on_login_failure():
    QMessageBox.warning(app.login_window, '警告', '登录失败，请检查邮箱和密码。')

@sio.on('register_success')
def on_register_success():
    QMessageBox.information(app.register_window, '提示', '注册成功！请登录。')
    app.login_window = LoginWindow()
    app.login_window.show()
    app.register_window.close()

@sio.on('register_failure')
def on_register_failure():
    QMessageBox.warning(app.register_window, '警告', '注册失败，请检查输入信息。')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    try:
        sio.connect('http://127.0.0.1:5000')
        app.login_window = LoginWindow()
        app.login_window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"连接服务端失败: {e}")