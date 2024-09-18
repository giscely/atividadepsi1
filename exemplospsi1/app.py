from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'  # Necessário para sessões e mensagens de flash

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redireciona para a rota de login se não estiver autenticado

# Classe User, necessária para o Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# Função para carregar o usuário
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'])
    return None

# Conexão com o banco de dados
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row  # Permite acesso por nome de coluna
    return conn

# Rota para a página inicial
@app.route('/')
def index():
    return render_template('index.html')

# Rota para registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash da senha
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash('Registro realizado com sucesso! Faça login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Usuário já existe. Tente outro.')
        finally:
            conn.close()

    return render_template('register.html')

# Rota para login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        # Verifica se o usuário existe e se a senha está correta
        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['username'])
            login_user(user_obj)  # Faz login do usuário
            return redirect(url_for('profile', username=username))
        else:
            flash('Usuário ou senha inválidos.')

    return render_template('login.html')

# Rota para o perfil do usuário
@app.route('/profile/<username>')
@login_required  # Garante que o usuário esteja logado
def profile(username):
    if current_user.username == username:  # Verifica se o usuário é o mesmo
        return render_template('profile.html', username=username)
    return redirect(url_for('login'))

# Rota de logout
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Faz logout do usuário
    return redirect(url_for('login'))