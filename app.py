import os
import sqlite3
import secrets
import logging
import json
import asyncio
from datetime import datetime, timedelta
from functools import wraps
from threading import Thread, Timer

# Flask imports
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, abort, send_file, g
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import BytesIO

# Utility imports
from dotenv import load_dotenv
import qrcode
from PIL import Image
import uuid
import pandas as pd # Used for potential future reporting, not strictly for core functionality here

# Aiogram imports (for Telegram bot)
from aiogram import Bot, Dispatcher, F, types, Router
from aiogram.filters import Command, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage # For simplicity, consider Redis/DB for production

# Load environment variables from .env file
load_dotenv()

# --- Flask App Configuration ---
app = Flask(__name__)
# Secret key for Flask sessions (CRITICAL for security, must be a long random string)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
# Флаг, указывающий, требуется ли настройка супер-администратора
app.config['SUPER_ADMIN_SETUP_REQUIRED'] = False
# Session configuration for Flask-Session
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True # Сессии будут постоянными до истечения срока
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=int(os.getenv("SESSION_LIFETIME_HOURS", 1))) # Настраиваемое время жизни сессии
Session(app)

# SocketIO configuration for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app) # Enable CORS for all origins, consider restricting in production

# --- Logging Configuration ---
# Get log file path from environment, default to 'kiosk.log'
LOG_FILE = os.getenv("LOG_FILE", "kiosk.log")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(LOG_FILE),
                        logging.StreamHandler()
                    ])

# --- Environment Variables (Constants) ---
# Database path from environment, default to 'regoffice.db'
DB_PATH = os.getenv("DB_PATH", "regoffice.db")
# Directory for QR codes
QR_CODE_FOLDER = os.getenv("QR_CODE_FOLDER", "qrcodes")
# Default admin credentials (FOR DEVELOPMENT ONLY, CHANGE IN PRODUCTION IMMEDIATELY!)
# ВНИМАНИЕ: Для production-среды эти значения должны быть изменены или удалены,
# а пароль супер-администратора должен устанавливаться при первом запуске!
# ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "superadmin") # Больше не используется для создания
# ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin") # Больше не используется для создания
# Flask debug mode (set to False for production)
DEBUG_MODE = os.getenv("DEBUG_MODE", "False").lower() == "true"
# Flask host and port
FLASK_RUN_HOST = os.getenv("FLASK_RUN_HOST", "0.0.0.0")
FLASK_RUN_PORT = int(os.getenv("FLASK_RUN_PORT", 5000))
# External URL for webhooks. For local testing, this will likely be localhost.
# For external access (e.g., Telegram bot links), you'd need ngrok or a public IP.
FLASK_EXTERNAL_URL = os.getenv("FLASK_EXTERNAL_URL")

# Ensure necessary directories exist
os.makedirs(QR_CODE_FOLDER, exist_ok=True)

# --- Telegram Bot Configuration (Single Bot for Polling) ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_BOT_USERNAME = os.getenv("TELEGRAM_BOT_USERNAME", "YourQueueBot") # Set a default username for /tg_bot_redirect

bot = None
dp = None
if TELEGRAM_BOT_TOKEN:
    try:
        storage = MemoryStorage()
        bot = Bot(token=TELEGRAM_BOT_TOKEN)
        dp = Dispatcher(storage=storage)
        logging.info("Telegram Bot (Aiogram) успешно инициализирован для режима polling.")
    except Exception as e:
        logging.error(f"Ошибка инициализации Telegram бота (Aiogram): {e}")
        bot = None
        dp = None
else:
    logging.warning("TELEGRAM_BOT_TOKEN не установлен в переменных окружения. Telegram бот не будет запущен.")

# --- Translation Loading ---
translations = {}
def load_translations():
    """Loads translations from translations.json."""
    global translations
    try:
        with open('translations.json', 'r', encoding='utf-8') as f:
            translations = json.load(f)
        logging.info("Translations loaded successfully.")
    except FileNotFoundError:
        logging.error("translations.json не найден. Переводы недоступны.")
        translations = {}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding translations.json: {e}.")
        translations = {}

# Helper function to get translated text
def get_text(lang, key, **kwargs):
    """Returns translated text for a given key and language."""
    # Fallback order: specific lang -> default (uz_lat) -> key itself
    return translations.get(lang, {}).get(key, translations.get('uz_lat', {}).get(key, key)).format(**kwargs)

# Load translations on app startup
load_translations()

# --- Database Helper Functions ---
def get_db():
    """Establishes and returns a database connection within the Flask app context.
    Uses Flask's `g` object to reuse connection for the same request."""
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

# Helper to close the database connection at the end of a request
@app.teardown_appcontext
def close_db_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database schema and creates a superadmin if not exists."""
    conn = get_db()
    c = conn.cursor()

    # Table for Branches (key for multi-branch architecture)
    c.execute('''
        CREATE TABLE IF NOT EXISTS branches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            location TEXT,
            telegram_bot_token TEXT UNIQUE, -- Kept for data, but not actively used for bot launch in polling mode
            bot_username TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Table for Users (operators, admins, clients) - branch_id added for isolation
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT, -- Hashed password for web users (operators, admins)
            role TEXT NOT NULL, -- 'super_admin', 'branch_admin', 'operator', 'client', 'viewer'
            branch_id INTEGER, -- NULL for super_admin, required for others
            telegram_user_id INTEGER UNIQUE, -- Made UNIQUE globally for simpler single-bot management
            current_ticket_id TEXT, -- Current active ticket for a client (Telegram user)
            is_vip BOOLEAN DEFAULT 0, -- Добавлено поле для VIP-статуса
            loyalty_points INTEGER DEFAULT 0, -- Добавлено поле для баллов лояльности
            is_available BOOLEAN DEFAULT 1, -- Добавлено для статуса доступности оператора
            available_start_time DATETIME, -- Время начала доступности
            available_end_time DATETIME,   -- Время окончания доступности
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            lang TEXT DEFAULT 'uz_lat', -- Добавлено поле для языка пользователя
            UNIQUE(username, branch_id), -- Username unique within a branch
            FOREIGN KEY (branch_id) REFERENCES branches (id) ON DELETE CASCADE
        )
    ''')
    try:
        c.execute("ALTER TABLE users ADD COLUMN is_vip BOOLEAN DEFAULT 0")
        logging.info("Column 'is_vip' added to 'users' table.")
    except sqlite3.OperationalError:
        pass # Column already exists
    try:
        c.execute("ALTER TABLE users ADD COLUMN loyalty_points INTEGER DEFAULT 0")
        logging.info("Column 'loyalty_points' added to 'users' table.")
    except sqlite3.OperationalError:
        pass # Column already exists
    try:
        c.execute("ALTER TABLE users ADD COLUMN is_available BOOLEAN DEFAULT 1")
        logging.info("Column 'is_available' added to 'users' table.")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN available_start_time DATETIME")
        logging.info("Column 'available_start_time' added to 'users' table.")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN available_end_time DATETIME")
        logging.info("Column 'available_end_time' added to 'users' table.")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN lang TEXT DEFAULT 'uz_lat'")
        logging.info("Column 'lang' added to 'users' table.")
    except sqlite3.OperationalError:
        pass # Column already exists

    # Table for Categories (hierarchical service grouping)
    c.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name_uz_lat TEXT NOT NULL,
            name_uz_cyr TEXT,
            name_ru TEXT,
            name_en TEXT,
            description_uz_lat TEXT,
            description_uz_cyr TEXT,
            description_ru TEXT,
            description_en TEXT,
            parent_id INTEGER,
            branch_id INTEGER NOT NULL,
            has_operators BOOLEAN NOT NULL DEFAULT 0, -- 0 for false, 1 for true
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(name_uz_lat, branch_id), -- Category name unique within a branch
            FOREIGN KEY (parent_id) REFERENCES categories (id) ON DELETE CASCADE,
            FOREIGN KEY (branch_id) REFERENCES branches (id) ON DELETE CASCADE
        )
    ''')
    # Индекс для ускорения поиска категорий по филиалу
    c.execute("CREATE INDEX IF NOT EXISTS idx_categories_branch_id ON categories (branch_id)")

    # Table for Services - branch_id added for isolation
    c.execute('''
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name_uz_lat TEXT NOT NULL,
            name_uz_cyr TEXT,
            name_ru TEXT,
            name_en TEXT,
            description_uz_lat TEXT,
            description_uz_cyr TEXT,
            description_ru TEXT,
            description_en TEXT,
            category_id INTEGER NOT NULL,
            operator_id INTEGER, -- Can be NULL (service not tied to specific operator)
            branch_id INTEGER NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1, -- 0 for inactive, 1 for active
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(name_uz_lat, branch_id), -- Service name unique within a branch
            FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE CASCADE,
            FOREIGN KEY (operator_id) REFERENCES users (id) ON DELETE SET NULL,
            FOREIGN KEY (branch_id) REFERENCES branches (id) ON DELETE CASCADE
        )
    ''')
    # Индекс для ускорения поиска услуг по категории и филиалу
    c.execute("CREATE INDEX IF NOT EXISTS idx_services_category_branch ON services (category_id, branch_id)")

    # Table for Tickets - branch_id added for isolation
    c.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            id TEXT PRIMARY KEY, -- Using UUID for ticket ID
            number TEXT NOT NULL, -- Human-readable ticket number (e.g., A001)
            service_id INTEGER NOT NULL,
            client_telegram_user_id INTEGER, -- Telegram ID of the client, if issued via bot
            operator_id INTEGER, -- Operator who called/served the ticket
            status TEXT NOT NULL DEFAULT 'waiting', -- 'waiting', 'called', 'finished', 'redirected', 'skipped', 'no_show', 'cancelled'
            start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            call_time DATETIME,
            finish_time DATETIME,
            redirect_time DATETIME,
            redirect_to_service_id INTEGER, -- The service it was redirected to
            branch_id INTEGER NOT NULL,
            qr_code_path TEXT, -- Path to the generated QR code image
            sort_order INTEGER, -- Для ручного управления очередью
            FOREIGN KEY (service_id) REFERENCES services (id) ON DELETE CASCADE,
            FOREIGN KEY (client_telegram_user_id) REFERENCES users (telegram_user_id) ON DELETE SET NULL,
            FOREIGN KEY (operator_id) REFERENCES users (id) ON DELETE SET NULL,
            FOREIGN KEY (redirect_to_service_id) REFERENCES services (id) ON DELETE SET NULL,
            FOREIGN KEY (branch_id) REFERENCES branches (id) ON DELETE CASCADE
        )
    ''')
    # Индексы для ускорения поиска талонов и сортировки очереди
    c.execute("CREATE INDEX IF NOT EXISTS idx_tickets_branch_status_start_time ON tickets (branch_id, status, start_time)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_tickets_client_telegram_user_id ON tickets (client_telegram_user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_tickets_operator_id ON tickets (operator_id)")
    try:
        c.execute("ALTER TABLE tickets ADD COLUMN sort_order INTEGER")
        logging.info("Column 'sort_order' added to 'tickets' table.")
    except sqlite3.OperationalError:
        pass # Column already exists

    # Table for Chat Messages - branch_id added for isolation
    c.execute('''
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT NOT NULL,
            sender_id INTEGER, -- Telegram user ID (for client) or user.id (for operator)
            sender_type TEXT NOT NULL, -- 'client' or 'operator'
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            branch_id INTEGER NOT NULL,
            FOREIGN KEY (ticket_id) REFERENCES tickets (id) ON DELETE CASCADE,
            FOREIGN KEY (branch_id) REFERENCES branches (id) ON DELETE CASCADE
        )
    ''')
    # Индекс для ускорения поиска сообщений чата по талону
    c.execute("CREATE INDEX IF NOT EXISTS idx_chat_messages_ticket_id ON chat_messages (ticket_id)")

    # Table for Feedback - branch_id added for isolation
    c.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT NOT NULL,
            rating INTEGER NOT NULL, -- 1 to 5 stars
            comment TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            branch_id INTEGER NOT NULL,
            FOREIGN KEY (ticket_id) REFERENCES tickets (id) ON DELETE CASCADE,
            FOREIGN KEY (branch_id) REFERENCES branches (id) ON DELETE CASCADE
        )
    ''')
    # Индекс для ускорения поиска отзывов по талону и филиалу
    c.execute("CREATE INDEX IF NOT EXISTS idx_feedback_ticket_branch ON feedback (ticket_id, branch_id)")

    # Table for Disputes - branch_id added for isolation
    c.execute('''
        CREATE TABLE IF NOT EXISTS disputes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT NOT NULL,
            comment TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending', -- 'pending', 'resolved', 'rejected'
            branch_id INTEGER NOT NULL,
            FOREIGN KEY (ticket_id) REFERENCES tickets (id) ON DELETE CASCADE,
            FOREIGN KEY (branch_id) REFERENCES branches (id) ON DELETE CASCADE
        )
    ''')
    # Индекс для ускорения поиска споров по талону и филиалу
    c.execute("CREATE INDEX IF NOT EXISTS idx_disputes_ticket_branch ON disputes (ticket_id, branch_id)")

    # Table for Admin Sessions (for web logins)
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            expiry_time DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    # Индекс для ускорения поиска сессий по session_id
    c.execute("CREATE INDEX IF NOT EXISTS idx_admin_sessions_session_id ON admin_sessions (session_id)")

    # Check for Super Admin user
    try:
        existing_super_admin = conn.execute("SELECT id FROM users WHERE role = 'super_admin' LIMIT 1").fetchone()
        if not existing_super_admin:
            app.config['SUPER_ADMIN_SETUP_REQUIRED'] = True
            logging.warning("Super admin user not found. Please navigate to /setup_super_admin to create one.")
        else:
            app.config['SUPER_ADMIN_SETUP_REQUIRED'] = False
            logging.info("Super admin user already exists.")
    except Exception as e:
        logging.error(f"Error checking for super admin: {e}")
        # Potentially set setup_required to true as a fallback if DB check fails
        app.config['SUPER_ADMIN_SETUP_REQUIRED'] = True
        logging.warning("Error during super admin check. Assuming setup is required. Navigate to /setup_super_admin.")

    conn.commit()
    # conn.close() # Не закрываем здесь, get_db() управляет этим

# --- Authentication Decorators ---
def login_required(role=None):
    """
    Decorator to ensure user is logged in and has the required role.
    Handles session management and redirects to login if unauthorized.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'admin_session_id' not in session:
                logging.warning("Access denied: No admin session ID found, redirecting to login.")
                if app.config.get('SUPER_ADMIN_SETUP_REQUIRED'):
                    return redirect(url_for('setup_super_admin'))
                return redirect(url_for('admin_login'))

            conn = get_db()
            session_id = session['admin_session_id']
            user_data = conn.execute("""
                SELECT u.id, u.username, u.role, u.branch_id
                FROM admin_sessions AS s JOIN users AS u ON s.user_id = u.id
                WHERE s.session_id = ? AND s.expiry_time > ?
            """, (session_id, datetime.now())).fetchone()
            # conn.close() # Managed by teardown_appcontext

            if user_data is None:
                logging.warning("Access denied: Invalid or expired session, redirecting to login.")
                session.pop('admin_session_id', None)
                session.pop('role', None)
                session.pop('user_id', None)
                session.pop('branch_id', None)
                if app.config.get('SUPER_ADMIN_SETUP_REQUIRED'):
                    return redirect(url_for('setup_super_admin'))
                return redirect(url_for('admin_login'))

            session['user_id'] = user_data['id']
            session['username'] = user_data['username']
            session['role'] = user_data['role']
            session['branch_id'] = user_data['branch_id']

            # Role-based access control
            if role:
                if user_data['role'] == 'super_admin':
                    pass # Super admin has access to everything
                elif user_data['role'] != role:
                    logging.warning(f"Access denied: User {user_data['username']} (role: {user_data['role']}) tried to access {role} role functionality.")
                    abort(403) # Forbidden

            # Branch-level access control for branch admins
            if user_data['role'] == 'branch_admin' and 'branch_id' in kwargs and kwargs['branch_id'] is not None:
                if user_data['branch_id'] != kwargs['branch_id']:
                    logging.warning(f"Access denied: Branch admin {user_data['username']} (branch: {user_data['branch_id']}) tried to access data from branch {kwargs['branch_id']}.")
                    abort(403) # Forbidden

            kwargs['current_user'] = dict(user_data)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Flask Routes ---

@app.route('/setup_super_admin', methods=['GET', 'POST'])
def setup_super_admin():
    # Проверяем, действительно ли нужна настройка или супер-админ уже создан
    with app.app_context():
        conn = get_db()
        existing_super_admin = conn.execute("SELECT id FROM users WHERE role = 'super_admin' LIMIT 1").fetchone()
        if existing_super_admin:
            app.config['SUPER_ADMIN_SETUP_REQUIRED'] = False # Обновляем флаг, если кто-то создал админа параллельно
            logging.info("Super admin already exists. Redirecting to login.")
            return redirect(url_for('admin_login'))

    if not app.config.get('SUPER_ADMIN_SETUP_REQUIRED', True): # Если флаг False, но админа нет (маловероятно)
        # Эта ветка на случай, если флаг был сброшен, но админ не создался
        logging.warning("Super admin setup page accessed, but setup flag is false and no admin exists. Re-evaluating.")
        # Можно добавить повторную проверку и установку флага, если нужно
        return redirect(url_for('admin_login'))


    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            return render_template('setup_super_admin.html', error="Все поля обязательны."), 400
        if password != confirm_password:
            return render_template('setup_super_admin.html', error="Пароли не совпадают."), 400
        if len(password) < 8: # Простое правило для длины пароля
            return render_template('setup_super_admin.html', error="Пароль должен быть не менее 8 символов."), 400

        conn = get_db()
        try:
            c = conn.cursor()
            # Еще раз проверим, не создал ли кто-то админа, пока форма была открыта
            existing_super_admin_check = c.execute("SELECT id FROM users WHERE role = 'super_admin' LIMIT 1").fetchone()
            if existing_super_admin_check:
                app.config['SUPER_ADMIN_SETUP_REQUIRED'] = False
                logging.info("Super admin was created concurrently. Redirecting to login.")
                return redirect(url_for('admin_login'))

            c.execute("INSERT INTO users (username, password_hash, role, branch_id) VALUES (?, ?, ?, NULL)",
                      (username, generate_password_hash(password), 'super_admin'))
            conn.commit()
            app.config['SUPER_ADMIN_SETUP_REQUIRED'] = False
            logging.info(f"Super admin user '{username}' created successfully.")
            # Можно добавить flash сообщение об успехе
            return redirect(url_for('admin_login')) # Перенаправляем на страницу входа
        except sqlite3.IntegrityError: # Хотя это не должно произойти из-за проверки выше
            conn.rollback()
            logging.error(f"Failed to create super admin '{username}' due to integrity error (should have been caught).")
            return render_template('setup_super_admin.html', error="Ошибка: Пользователь с таким именем уже существует или другая ошибка целостности."), 409
        except Exception as e:
            conn.rollback()
            logging.error(f"Error creating super admin '{username}': {e}")
            return render_template('setup_super_admin.html', error=f"Не удалось создать супер-администратора: {e}"), 500
        # finally: # Managed by teardown_appcontext
        #     conn.close()
    
    # Для GET запроса или если POST неудачен и нужно снова показать форму
    return render_template('setup_super_admin.html')

@app.route('/')
def index():
    """Renders the main client-facing service selection page."""
    if app.config.get('SUPER_ADMIN_SETUP_REQUIRED'):
        return redirect(url_for('setup_super_admin'))
    return render_template('index.html')

@app.route('/display')
def display_page():
    """
    Renders the public display board page.
    Requires a branch_id to display specific branch queue.
    """
    if app.config.get('SUPER_ADMIN_SETUP_REQUIRED'):
        return redirect(url_for('setup_super_admin'))
    branch_id = request.args.get('branch_id', type=int)
    if not branch_id:
        logging.error("Display page accessed without branch ID.")
        return "Error: Please specify a branch ID (e.g., /display?branch_id=1)", 400

    conn = get_db()
    branch_name_row = conn.execute("SELECT name FROM branches WHERE id = ?", (branch_id,)).fetchone()
    # conn.close()

    if not branch_name_row:
        logging.error(f"Display page: Branch with ID {branch_id} not found.")
        return "Error: Branch not found.", 404

    return render_template('display.html', branch_id=branch_id, branch_name=branch_name_row['name'])

@app.route('/operator')
@login_required(role='operator')
def operator_page(current_user):
    """Renders the operator dashboard."""
    # Флаг SUPER_ADMIN_SETUP_REQUIRED проверяется в login_required
    return render_template('operator.html', server_url=request.url_root.rstrip('/'))

@app.route('/admin')
@login_required(role='branch_admin')
def admin_page(current_user):
    """Renders the branch admin dashboard."""
    # Флаг SUPER_ADMIN_SETUP_REQUIRED проверяется в login_required
    return render_template('admin.html', server_url=request.url_root.rstrip('/'))

@app.route('/super_admin')
@login_required(role='super_admin')
def super_admin_page(current_user):
    """Renders the super admin panel for managing branches and global settings."""
    # Флаг SUPER_ADMIN_SETUP_REQUIRED проверяется в login_required
    # Если это супер-админ, то страница настройки ему не нужна, он уже настроен
    return render_template('super_admin.html', server_url=request.url_root.rstrip('/'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login for web interface (operators, admins)."""
    if app.config.get('SUPER_ADMIN_SETUP_REQUIRED'):
        # Проверяем, не был ли админ создан только что другим запросом
        with app.app_context(): # Нужно для get_db() вне контекста запроса Flask
            conn = get_db()
            existing_super_admin = conn.execute("SELECT id FROM users WHERE role = 'super_admin' LIMIT 1").fetchone()
            if not existing_super_admin:
                return redirect(url_for('setup_super_admin'))
            else: # Админ был создан, сбрасываем флаг
                app.config['SUPER_ADMIN_SETUP_REQUIRED'] = False

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('login.html', error="Имя пользователя и пароль обязательны."), 400

        conn = get_db()
        user = conn.execute("SELECT id, password_hash, role, branch_id FROM users WHERE username = ?", (username,)).fetchone()
        # conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session_id = secrets.token_hex(32)
            # Use configured session lifetime
            expiry_time = datetime.now() + app.config["PERMANENT_SESSION_LIFETIME"]

            # conn = get_db() # Already got connection above
            try:
                conn.execute("INSERT INTO admin_sessions (session_id, user_id, expiry_time) VALUES (?, ?, ?)",
                             (session_id, user['id'], expiry_time))
                conn.commit()
            except Exception as e:
                conn.rollback()
                logging.error(f"Error creating admin session for user {username}: {e}")
                return render_template('login.html', error="Ошибка входа."), 500 # Login error

            session['admin_session_id'] = session_id
            session['user_id'] = user['id']
            session['username'] = username
            session['role'] = user['role']
            session['branch_id'] = user['branch_id']
            logging.info(f"User {username} logged in successfully with role {user['role']}.")

            if user['role'] == 'super_admin':
                return redirect(url_for('super_admin_page'))
            elif user['role'] == 'branch_admin':
                return redirect(url_for('admin_page'))
            elif user['role'] in ['operator', 'viewer']:
                return redirect(url_for('operator_page'))
            else:
                logging.warning(f"User {username} has unknown role: {user['role']}.")
                return render_template('login.html', error="Неизвестная роль пользователя."), 403
        else:
            logging.warning(f"Failed login attempt for username: {username}.")
            return render_template('login.html', error="Неверное имя пользователя или пароль.")
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    """Handles admin specific login (redirects to admin/super_admin dashboard)."""
    if app.config.get('SUPER_ADMIN_SETUP_REQUIRED'):
        with app.app_context(): # Нужно для get_db() вне контекста запроса Flask
            conn = get_db()
            existing_super_admin = conn.execute("SELECT id FROM users WHERE role = 'super_admin' LIMIT 1").fetchone()
            if not existing_super_admin:
                return redirect(url_for('setup_super_admin'))
            else:
                app.config['SUPER_ADMIN_SETUP_REQUIRED'] = False

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('admin_login.html', error="Имя пользователя и пароль обязательны."), 400

        conn = get_db()
        user = conn.execute("SELECT id, password_hash, role, branch_id FROM users WHERE username = ?", (username,)).fetchone()
        # conn.close()

        if user and check_password_hash(user['password_hash'], password):
            if user['role'] not in ['super_admin', 'branch_admin']:
                logging.warning(f"Unauthorized admin login attempt for user {username} with role {user['role']}.")
                return render_template('admin_login.html', error="Доступ запрещен: Только администраторы могут войти здесь."), 403

            session_id = secrets.token_hex(32)
            expiry_time = datetime.now() + app.config["PERMANENT_SESSION_LIFETIME"]

            # conn = get_db() # Already got connection above
            try:
                conn.execute("INSERT INTO admin_sessions (session_id, user_id, expiry_time) VALUES (?, ?, ?)",
                             (session_id, user['id'], expiry_time))
                conn.commit()
            except Exception as e:
                conn.rollback()
                logging.error(f"Error creating admin session for user {username}: {e}")
                return render_template('admin_login.html', error="Ошибка входа."), 500

            session['admin_session_id'] = session_id
            session['user_id'] = user['id']
            session['username'] = username
            session['role'] = user['role']
            session['branch_id'] = user['branch_id']
            logging.info(f"Admin user {username} logged in successfully with role {user['role']}.")

            if user['role'] == 'super_admin':
                return redirect(url_for('super_admin_page'))
            else: # branch_admin
                return redirect(url_for('admin_page'))
        else:
            logging.warning(f"Failed admin login attempt for username: {username}.")
            return render_template('admin_login.html', error="Неверное имя пользователя или пароль.")
    return render_template('admin_login.html')

@app.route('/logout')
@login_required() # Any logged-in user can logout
def logout(current_user):
    """Logs out the current user by clearing session data."""
    if 'admin_session_id' in session:
        conn = get_db()
        try:
            conn.execute("DELETE FROM admin_sessions WHERE session_id = ?", (session['admin_session_id'],))
            conn.commit()
            logging.info(f"User {session.get('username')} logged out.")
        except Exception as e:
            conn.rollback()
            logging.error(f"Error deleting admin session for {session.get('username')}: {e}")
        # conn.close() # Managed by teardown_appcontext
        session.pop('admin_session_id', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('branch_id', None)
    return redirect(url_for('login'))

@app.route('/feedback/<string:ticket_id>') # Ticket ID is TEXT (UUID) now
def feedback_page(ticket_id):
    """Renders the feedback page for a given ticket."""
    if app.config.get('SUPER_ADMIN_SETUP_REQUIRED'): # Добавлено для последовательности
        return redirect(url_for('setup_super_admin'))
    conn = get_db()
    ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    # conn.close()
    if not ticket:
        logging.warning(f"Feedback page accessed for non-existent ticket ID: {ticket_id}")
        abort(404)
    return render_template('feedback.html', ticket_id=ticket_id)

@app.route('/dispute/<string:ticket_id>') # Ticket ID is TEXT (UUID) now
def dispute_page(ticket_id):
    """Renders the dispute page for a given ticket."""
    if app.config.get('SUPER_ADMIN_SETUP_REQUIRED'): # Добавлено для последовательности
        return redirect(url_for('setup_super_admin'))
    conn = get_db()
    ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    # conn.close()
    if not ticket:
        logging.warning(f"Dispute page accessed for non-existent ticket ID: {ticket_id}")
        abort(404)
    return render_template('dispute.html', ticket_id=ticket_id)

@app.route('/chat/<string:ticket_id>') # Ticket ID is TEXT (UUID) now
def chat_page(ticket_id):
    """Renders the chat page for a given ticket."""
    if app.config.get('SUPER_ADMIN_SETUP_REQUIRED'): # Добавлено для последовательности
        return redirect(url_for('setup_super_admin'))
    conn = get_db()
    ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    # conn.close()
    if not ticket:
        logging.warning(f"Chat page accessed for non-existent ticket ID: {ticket_id}")
        abort(404)
    return render_template('chat.html', ticket_id=ticket_id)

@app.route('/tg_bot_redirect')
def tg_bot_redirect():
    """
    Redirects to Telegram bot with start parameter for ticket-specific actions.
    This route will only work if FLASK_EXTERNAL_URL is set and publicly accessible.
    For local development without ngrok, this link will not work externally.
    """
    if app.config.get('SUPER_ADMIN_SETUP_REQUIRED'): # Добавлено для последовательности
        return redirect(url_for('setup_super_admin'))
    ticket_id = request.args.get('ticket_id')
    if ticket_id and TELEGRAM_BOT_USERNAME:
        # Construct the internal URL that the bot will process
        redirect_url = f"https://t.me/{TELEGRAM_BOT_USERNAME}?start=ticket_{ticket_id}"
        logging.info(f"Telegram bot redirect for ticket {ticket_id}: {redirect_url}.")
        return redirect(redirect_url)
    logging.warning("Attempted Telegram bot redirect without ticket_id or bot username. Redirecting to index.")
    return redirect(url_for('index'))


# --- API Endpoints ---

# --- Branch Management API (Super Admin) ---
@app.route('/api/branches', methods=['GET'])
@login_required(role='super_admin')
def get_branches(current_user):
    """Returns a list of all branches."""
    conn = get_db()
    branches = conn.execute("SELECT id, name, location, telegram_bot_token, bot_username FROM branches").fetchall()
    # conn.close()
    logging.info(f"Super admin {current_user['username']} fetched all branches.")
    return jsonify([dict(row) for row in branches])

@app.route('/api/add_branch', methods=['POST'])
@login_required(role='super_admin')
def add_branch(current_user):
    """Adds a new branch."""
    data = request.json
    name = data.get('name')
    location = data.get('location')
    telegram_bot_token = data.get('telegram_bot_token') # Not used for polling bot, but can be stored
    bot_username = data.get('bot_username')

    if not name:
        logging.warning(f"Super admin {current_user['username']} attempted to add branch without name.")
        return jsonify({'error': 'Missing branch name'}), 400

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO branches (name, location, telegram_bot_token, bot_username) VALUES (?, ?, ?, ?)",
                  (name, location, telegram_bot_token, bot_username))
        branch_id = c.lastrowid
        conn.commit()
        logging.info(f"Super admin {current_user['username']} added new branch: {name} (ID: {branch_id}).")
        return jsonify({'message': 'Branch added successfully', 'branch_id': branch_id}), 201
    except sqlite3.IntegrityError:
        conn.rollback()
        logging.warning(f"Super admin {current_user['username']} attempted to add duplicate branch name or bot token: {name}.")
        return jsonify({'error': 'Branch name or bot token already exists'}), 409
    except Exception as e:
        conn.rollback()
        logging.error(f"Super admin {current_user['username']} failed to add branch {name}: {e}")
        return jsonify({'error': f'Failed to add branch: {e}'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/update_branch/<int:branch_id>', methods=['PUT'])
@login_required(role='super_admin')
def update_branch(branch_id, current_user):
    """Updates an existing branch's details."""
    data = request.json
    name = data.get('name')
    location = data.get('location')
    telegram_bot_token = data.get('telegram_bot_token')
    bot_username = data.get('bot_username')

    conn = get_db()
    current_branch = conn.execute("SELECT id FROM branches WHERE id = ?", (branch_id,)).fetchone()
    if not current_branch:
        # conn.close()
        logging.warning(f"Super admin {current_user['username']} attempted to update non-existent branch ID: {branch_id}.")
        return jsonify({'error': 'Branch not found'}), 404

    try:
        update_fields = []
        update_values = []
        if name is not None:
            update_fields.append("name = ?")
            update_values.append(name)
        if location is not None:
            update_fields.append("location = ?")
            update_values.append(location)
        if telegram_bot_token is not None:
            update_fields.append("telegram_bot_token = ?")
            update_values.append(telegram_bot_token)
        if bot_username is not None:
            update_fields.append("bot_username = ?")
            update_values.append(bot_username)

        if not update_fields:
            logging.info(f"Super admin {current_user['username']} attempted to update branch {branch_id} with no changes.")
            return jsonify({'message': 'No fields to update'}), 200

        update_query = f"UPDATE branches SET {', '.join(update_fields)} WHERE id = ?"
        update_values.append(branch_id)

        conn.execute(update_query, tuple(update_values))
        conn.commit()
        logging.info(f"Super admin {current_user['username']} updated branch ID {branch_id}.")
        return jsonify({'message': 'Branch updated successfully'}), 200
    except sqlite3.IntegrityError:
        conn.rollback()
        logging.warning(f"Super admin {current_user['username']} attempted to update branch {branch_id} with duplicate name or bot token.")
        return jsonify({'error': 'Branch name or bot token already exists'}), 409
    except Exception as e:
        conn.rollback()
        logging.error(f"Super admin {current_user['username']} failed to update branch {branch_id}: {e}")
        return jsonify({'error': f'Failed to update branch: {e}'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/delete_branch/<int:branch_id>', methods=['DELETE'])
@login_required(role='super_admin')
def delete_branch(branch_id, current_user):
    """Deletes a branch and all associated data."""
    conn = get_db()
    try:
        conn.execute("DELETE FROM branches WHERE id = ?", (branch_id,))
        conn.commit()

        if conn.changes() == 0:
            logging.warning(f"Super admin {current_user['username']} attempted to delete non-existent branch ID: {branch_id}.")
            return jsonify({'error': 'Branch not found'}), 404

        logging.info(f"Super admin {current_user['username']} deleted branch ID {branch_id} and all associated data.")
        return jsonify({'message': 'Branch and all associated data deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Super admin {current_user['username']} failed to delete branch {branch_id}: {e}")
        return jsonify({'error': f'Failed to delete branch: {e}'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

# --- Category Management API (Branch Admin) ---
@app.route('/api/categories/<int:branch_id>', methods=['GET'])
@login_required(role='branch_admin')
def get_categories_by_branch(branch_id, current_user):
    """Returns categories for a specific branch."""
    conn = get_db()
    categories = conn.execute("""
        SELECT id, name_uz_lat, name_uz_cyr, name_ru, name_en, description_uz_lat, description_uz_cyr, description_ru, description_en, parent_id, has_operators
        FROM categories
        WHERE branch_id = ?
    """, (branch_id,)).fetchall()
    # conn.close()
    logging.info(f"Branch admin {current_user['username']} fetched categories for branch {branch_id}.")
    return jsonify([dict(row) for row in categories])

@app.route('/api/add_category', methods=['POST'])
@login_required(role='branch_admin')
def add_category(current_user):
    """Adds a new category for a specific branch."""
    data = request.json
    name_uz_lat = data.get('name_uz_lat')
    name_uz_cyr = data.get('name_uz_cyr')
    name_ru = data.get('name_ru')
    name_en = data.get('name_en')
    description_uz_lat = data.get('description_uz_lat')
    description_uz_cyr = data.get('description_uz_cyr')
    description_ru = data.get('description_ru')
    description_en = data.get('description_en')
    parent_id = data.get('parent_id')
    branch_id = data.get('branch_id')
    has_operators = data.get('has_operators', False)

    if not all([name_uz_lat, branch_id]):
        logging.warning(f"Branch admin {current_user['username']} attempted to add category without name or branch ID.")
        return jsonify({"error": "Missing category name or branch ID"}), 400

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO categories (name_uz_lat, name_uz_cyr, name_ru, name_en, description_uz_lat, description_uz_cyr, description_ru, description_en, parent_id, branch_id, has_operators)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name_uz_lat, name_uz_cyr, name_ru, name_en, description_uz_lat, description_uz_cyr, description_ru, description_en, parent_id, branch_id, has_operators))
        conn.commit()
        category_id = c.lastrowid
        logging.info(f"Branch admin {current_user['username']} added new category: {name_uz_lat} (ID: {category_id}, Branch: {branch_id}).")
        return jsonify({"message": "Category added successfully", "id": category_id}), 201
    except sqlite3.IntegrityError:
        conn.rollback()
        logging.warning(f"Branch admin {current_user['username']} attempted to add duplicate category name {name_uz_lat} in branch {branch_id} or invalid parent_id.")
        return jsonify({"error": "Category with this name already exists in this branch or invalid parent_id"}), 400
    except Exception as e:
        conn.rollback()
        logging.error(f"Branch admin {current_user['username']} failed to add category {name_uz_lat} for branch {branch_id}: {e}")
        return jsonify({"error": f"Failed to add category: {e}"}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/update_category/<int:category_id>', methods=['PUT'])
@login_required(role='branch_admin')
def update_category(category_id, current_user):
    """Updates an existing category for a specific branch."""
    data = request.json
    name_uz_lat = data.get('name_uz_lat')
    name_uz_cyr = data.get('name_uz_cyr')
    name_ru = data.get('name_ru')
    name_en = data.get('name_en')
    description_uz_lat = data.get('description_uz_lat')
    description_uz_cyr = data.get('description_uz_cyr')
    description_ru = data.get('description_ru')
    description_en = data.get('description_en')
    parent_id = data.get('parent_id')
    has_operators = data.get('has_operators')
    branch_id = current_user['branch_id']

    conn = get_db()
    try:
        c = conn.cursor()
        category = c.execute("SELECT id FROM categories WHERE id = ? AND branch_id = ?", (category_id, branch_id)).fetchone()
        if not category:
            # conn.close()
            logging.warning(f"Branch admin {current_user['username']} attempted to update non-existent category ID {category_id} in branch {branch_id}.")
            return jsonify({"error": "Category not found in your branch"}), 404

        update_fields = []
        update_values = []
        if name_uz_lat is not None: update_fields.append("name_uz_lat = ?"); update_values.append(name_uz_lat)
        if name_uz_cyr is not None: update_fields.append("name_uz_cyr = ?"); update_values.append(name_uz_cyr)
        if name_ru is not None: update_fields.append("name_ru = ?"); update_values.append(name_ru)
        if name_en is not None: update_fields.append("name_en = ?"); update_values.append(name_en)
        if description_uz_lat is not None: update_fields.append("description_uz_lat = ?"); update_values.append(description_uz_lat)
        if description_uz_cyr is not None: update_fields.append("description_uz_cyr = ?"); update_values.append(description_uz_cyr)
        if description_ru is not None: update_fields.append("description_ru = ?"); update_values.append(description_ru)
        if description_en is not None: update_fields.append("description_en = ?"); update_values.append(description_en)
        if parent_id is not None: update_fields.append("parent_id = ?"); update_values.append(parent_id)
        if has_operators is not None: update_fields.append("has_operators = ?"); update_values.append(has_operators)

        if not update_fields:
            logging.info(f"Branch admin {current_user['username']} attempted to update category {category_id} with no changes.")
            return jsonify({"message": "No fields to update"}), 200

        update_query = f"UPDATE categories SET {', '.join(update_fields)} WHERE id = ? AND branch_id = ?"
        update_values.extend([category_id, branch_id])

        c.execute(update_query, tuple(update_values))
        conn.commit()

        if c.rowcount == 0:
            logging.warning(f"Branch admin {current_user['username']} failed to update category {category_id} (not found or no changes).")
            return jsonify({"error": "Category not found or no changes made"}), 404
        logging.info(f"Branch admin {current_user['username']} updated category ID {category_id} in branch {branch_id}.")
        return jsonify({"message": "Category updated successfully"}), 200
    except sqlite3.IntegrityError:
        conn.rollback()
        logging.warning(f"Branch admin {current_user['username']} attempted to update category {category_id} with invalid parent_id or duplicate name.")
        return jsonify({"error": "Invalid parent_id or duplicate name in this branch"}), 400
    except Exception as e:
        conn.rollback()
        logging.error(f"Branch admin {current_user['username']} failed to update category {category_id} in branch {branch_id}: {e}")
        return jsonify({"error": f"Failed to update category: {e}"}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/delete_category/<int:category_id>', methods=['DELETE'])
@login_required(role='branch_admin')
def delete_category(category_id, current_user):
    """Deletes a category from a specific branch."""
    branch_id = current_user['branch_id']
    conn = get_db()
    try:
        c = conn.cursor()
        category = c.execute("SELECT id FROM categories WHERE id = ? AND branch_id = ?", (category_id, branch_id)).fetchone()
        if not category:
            # conn.close()
            logging.warning(f"Branch admin {current_user['username']} attempted to delete non-existent category ID {category_id} in branch {branch_id}.")
            return jsonify({"error": "Category not found in your branch"}), 404

        sub_categories_count = c.execute("SELECT COUNT(*) FROM categories WHERE parent_id = ? AND branch_id = ?", (category_id, branch_id)).fetchone()[0]
        services_count = c.execute("SELECT COUNT(*) FROM services WHERE category_id = ? AND branch_id = ?", (category_id, branch_id)).fetchone()[0]

        if sub_categories_count > 0 or services_count > 0:
            logging.warning(f"Branch admin {current_user['username']} attempted to delete category {category_id} with existing subcategories or services.")
            return jsonify({"error": "Cannot delete category with existing subcategories or services"}), 400

        c.execute("DELETE FROM categories WHERE id = ? AND branch_id = ?", (category_id, branch_id))
        conn.commit()
        if c.rowcount == 0:
            logging.warning(f"Branch admin {current_user['username']} failed to delete category {category_id} (not found or no changes).")
            return jsonify({"error": "Category not found or no changes made"}), 404
        logging.info(f"Branch admin {current_user['username']} deleted category ID {category_id} in branch {branch_id}.")
        return jsonify({"message": "Category deleted successfully"}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Branch admin {current_user['username']} failed to delete category {category_id} in branch {branch_id}: {e}")
        return jsonify({"error": f"Failed to delete category: {e}"}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

# --- Service Management API (Branch Admin) ---
@app.route('/api/services/<int:branch_id>', methods=['GET'])
@login_required(role='branch_admin')
def get_services_by_branch(branch_id, current_user):
    """Returns services for a specific branch."""
    conn = get_db()
    services = conn.execute("""
        SELECT s.id, s.name_uz_lat, s.name_uz_cyr, s.name_ru, s.name_en, s.description_uz_lat, s.description_uz_cyr, s.description_ru, s.description_en, s.category_id, s.is_active,
               u.username as operator_username
        FROM services s
        LEFT JOIN users u ON s.operator_id = u.id
        WHERE s.branch_id = ?
    """, (branch_id,)).fetchall()
    # conn.close()
    logging.info(f"Branch admin {current_user['username']} fetched services for branch {branch_id}.")
    return jsonify([dict(row) for row in services])

@app.route('/api/add_service', methods=['POST'])
@login_required(role='branch_admin')
def add_service(current_user):
    """Adds a new service for a specific branch."""
    data = request.json
    name_uz_lat = data.get('name_uz_lat')
    name_uz_cyr = data.get('name_uz_cyr')
    name_ru = data.get('name_ru')
    name_en = data.get('name_en')
    description_uz_lat = data.get('description_uz_lat')
    description_uz_cyr = data.get('description_uz_cyr')
    description_ru = data.get('description_ru')
    description_en = data.get('description_en')
    category_id = data.get('category_id')
    operator_id = data.get('operator_id')
    branch_id = data.get('branch_id')
    is_active = data.get('is_active', True)

    if not all([name_uz_lat, category_id, branch_id]):
        logging.warning(f"Branch admin {current_user['username']} attempted to add service without name, category ID, or branch ID.")
        return jsonify({"error": "Missing service name, category ID, or branch ID"}), 400

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO services (name_uz_lat, name_uz_cyr, name_ru, name_en,
                                  description_uz_lat, description_uz_cyr, description_ru, description_en,
                                  category_id, operator_id, branch_id, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name_uz_lat, name_uz_cyr, name_ru, name_en,
              description_uz_lat, description_uz_cyr, description_ru, description_en,
              category_id, operator_id, branch_id, is_active))
        conn.commit()
        service_id = c.lastrowid
        logging.info(f"Branch admin {current_user['username']} added new service: {name_uz_lat} (ID: {service_id}, Branch: {branch_id}).")
        return jsonify({"message": "Service added successfully", "id": service_id}), 201
    except sqlite3.IntegrityError:
        conn.rollback()
        logging.warning(f"Branch admin {current_user['username']} attempted to add duplicate service name {name_uz_lat} in branch {branch_id} or invalid category/operator ID.")
        return jsonify({"error": "Service with this name already exists in this branch or invalid category/operator ID"}), 400
    except Exception as e:
        conn.rollback()
        logging.error(f"Branch admin {current_user['username']} failed to add service {name_uz_lat} for branch {branch_id}: {e}")
        return jsonify({"error": f"Failed to add service: {e}"}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/update_service/<int:service_id>', methods=['PUT'])
@login_required(role='branch_admin')
def update_service(service_id, current_user):
    """Updates an existing service for a specific branch."""
    data = request.json
    name_uz_lat = data.get('name_uz_lat')
    name_uz_cyr = data.get('name_uz_cyr')
    name_ru = data.get('name_ru')
    name_en = data.get('name_en')
    description_uz_lat = data.get('description_uz_lat')
    description_uz_cyr = data.get('description_uz_cyr')
    description_ru = data.get('description_ru')
    description_en = data.get('description_en')
    category_id = data.get('category_id')
    operator_id = data.get('operator_id')
    is_active = data.get('is_active')
    branch_id = current_user['branch_id']

    conn = get_db()
    try:
        c = conn.cursor()
        service = c.execute("SELECT id FROM services WHERE id = ? AND branch_id = ?", (service_id, branch_id)).fetchone()
        if not service:
            # conn.close()
            logging.warning(f"Branch admin {current_user['username']} attempted to update non-existent service ID {service_id} in branch {branch_id}.")
            return jsonify({"error": "Service not found in your branch"}), 404

        update_fields = []
        update_values = []
        if name_uz_lat is not None: update_fields.append("name_uz_lat = ?"); update_values.append(name_uz_lat)
        if name_uz_cyr is not None: update_fields.append("name_uz_cyr = ?"); update_values.append(name_uz_cyr)
        if name_ru is not None: update_fields.append("name_ru = ?"); update_values.append(name_ru)
        if name_en is not None: update_fields.append("name_en = ?"); update_values.append(name_en)
        if description_uz_lat is not None: update_fields.append("description_uz_lat = ?"); update_values.append(description_uz_lat)
        if description_uz_cyr is not None: update_fields.append("description_uz_cyr = ?"); update_values.append(description_uz_cyr)
        if description_ru is not None: update_fields.append("description_ru = ?"); update_values.append(description_ru)
        if description_en is not None: update_fields.append("description_en = ?"); update_values.append(description_en)
        if category_id is not None: update_fields.append("category_id = ?"); update_values.append(category_id)
        if operator_id is not None: update_fields.append("operator_id = ?"); update_values.append(operator_id)
        if is_active is not None: update_fields.append("is_active = ?"); update_values.append(is_active)

        if not update_fields:
            logging.info(f"Branch admin {current_user['username']} attempted to update service {service_id} with no changes.")
            return jsonify({"message": "No fields to update"}), 200

        update_query = f"UPDATE services SET {', '.join(update_fields)} WHERE id = ? AND branch_id = ?"
        update_values.extend([service_id, branch_id])

        c.execute(update_query, tuple(update_values))
        conn.commit()

        if c.rowcount == 0:
            logging.warning(f"Branch admin {current_user['username']} failed to update service {service_id} (not found or no changes).")
            return jsonify({"error": "Service not found or no changes made"}), 404
        logging.info(f"Branch admin {current_user['username']} updated service ID {service_id} in branch {branch_id}.")
        return jsonify({"message": "Service updated successfully"}), 200
    except sqlite3.IntegrityError:
        conn.rollback()
        logging.warning(f"Branch admin {current_user['username']} attempted to update service {service_id} with duplicate name or invalid category/operator ID.")
        return jsonify({"error": "Service with this name already exists in this branch or invalid category/operator ID"}), 400
    except Exception as e:
        conn.rollback()
        logging.error(f"Branch admin {current_user['username']} failed to update service {service_id} in branch {branch_id}: {e}")
        return jsonify({"error": f"Failed to update service: {e}"}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/delete_service/<int:service_id>', methods=['DELETE'])
@login_required(role='branch_admin')
def delete_service(service_id, current_user):
    """Deletes a service from a specific branch."""
    branch_id = current_user['branch_id']
    conn = get_db()
    try:
        c = conn.cursor()
        service = c.execute("SELECT id FROM services WHERE id = ? AND branch_id = ?", (service_id, branch_id)).fetchone()
        if not service:
            # conn.close()
            logging.warning(f"Branch admin {current_user['username']} attempted to delete non-existent service ID {service_id} in branch {branch_id}.")
            return jsonify({"error": "Service not found in your branch"}), 404

        c.execute("DELETE FROM services WHERE id = ? AND branch_id = ?", (service_id, branch_id))
        conn.commit()
        if c.rowcount == 0:
            logging.warning(f"Branch admin {current_user['username']} failed to delete service {service_id} (not found or no changes).")
            return jsonify({"error": "Service not found or no changes made"}), 404
        logging.info(f"Branch admin {current_user['username']} deleted service ID {service_id} in branch {branch_id}.")
        return jsonify({"message": "Service deleted successfully"}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Branch admin {current_user['username']} failed to delete service {service_id} in branch {branch_id}: {e}")
        return jsonify({"error": f"Failed to delete service: {e}"}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

# --- User/Operator Management API (Branch Admin/Super Admin) ---
@app.route('/api/users/<int:branch_id>', methods=['GET'])
@login_required(role='branch_admin')
def get_users_by_branch(branch_id, current_user):
    """Returns users (operators, viewers) for a specific branch."""
    conn = get_db()
    users = conn.execute("""
        SELECT id, username, role, telegram_user_id, is_vip, loyalty_points, is_available, available_start_time, available_end_time
        FROM users
        WHERE branch_id = ? AND role NOT IN ('super_admin', 'client')
    """, (branch_id,)).fetchall()
    # conn.close()
    logging.info(f"Branch admin {current_user['username']} fetched users for branch {branch_id}.")
    return jsonify([dict(row) for row in users])

@app.route('/api/add_user', methods=['POST'])
@login_required(role='branch_admin') # Super admin can also use this
def add_user(current_user):
    """Adds a new user (operator/viewer/branch_admin) for a specific branch."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    branch_id = data.get('branch_id')
    telegram_user_id = data.get('telegram_user_id')

    if current_user['role'] == 'branch_admin' and current_user['branch_id'] != branch_id:
        logging.warning(f"Branch admin {current_user['username']} attempted to add user to another branch ({branch_id}).")
        return jsonify({'error': 'Branch admin cannot add users to other branches'}), 403
    if current_user['role'] == 'branch_admin' and role not in ['operator', 'viewer']:
        logging.warning(f"Branch admin {current_user['username']} attempted to create user with unauthorized role {role}.")
        return jsonify({'error': 'Branch admin can only create operator or viewer roles'}), 403
    # Super admin can create branch_admin as well
    if current_user['role'] == 'super_admin' and role not in ['operator', 'viewer', 'branch_admin']:
        logging.warning(f"Super admin {current_user['username']} attempted to create user with unauthorized role {role}.")
        return jsonify({'error': 'Super admin can only create operator, viewer, or branch_admin roles'}), 403


    if not all([username, password, role, branch_id]):
        logging.warning(f"User {current_user['username']} attempted to add user with missing data.")
        return jsonify({'error': 'Missing user data'}), 400

    hashed_password = generate_password_hash(password)
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password_hash, role, branch_id, telegram_user_id) VALUES (?, ?, ?, ?, ?)",
                  (username, hashed_password, role, branch_id, telegram_user_id))
        user_id = c.lastrowid
        conn.commit()
        logging.info(f"User {current_user['username']} added new user: {username} (ID: {user_id}, Role: {role}, Branch: {branch_id}).")
        return jsonify({'message': 'User added successfully', 'user_id': user_id}), 201
    except sqlite3.IntegrityError:
        conn.rollback()
        logging.warning(f"User {current_user['username']} attempted to add user {username} with duplicate username or Telegram user ID.")
        return jsonify({'error': 'Username or Telegram user ID already exists for this branch/globally'}), 409
    except Exception as e:
        conn.rollback()
        logging.error(f"User {current_user['username']} failed to add user {username}: {e}")
        return jsonify({'error': 'Failed to add user'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/update_user/<int:user_id>', methods=['PUT'])
@login_required(role='branch_admin') # Super admin can update all users too
def update_user(user_id, current_user):
    """Updates an existing user's details for a specific branch."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    telegram_user_id = data.get('telegram_user_id')
    is_vip = data.get('is_vip')
    loyalty_points = data.get('loyalty_points')
    is_available = data.get('is_available')
    available_start_time = data.get('available_start_time')
    available_end_time = data.get('available_end_time')


    conn = get_db()
    user_to_update = conn.execute("SELECT branch_id, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_to_update:
        # conn.close()
        logging.warning(f"User {current_user['username']} attempted to update non-existent user ID: {user_id}.")
        return jsonify({'error': 'User not found'}), 404

    if current_user['role'] == 'branch_admin':
        if user_to_update['branch_id'] != current_user['branch_id']:
            # conn.close()
            logging.warning(f"Branch admin {current_user['username']} attempted to update user {user_id} in another branch.")
            return jsonify({'error': 'Branch admin cannot update users in other branches'}), 403
        if user_to_update['role'] in ['super_admin', 'branch_admin'] or (role and (role == 'branch_admin' or role == 'super_admin')):
            # conn.close()
            logging.warning(f"Branch admin {current_user['username']} attempted to update an admin user {user_id} or assign admin role.")
            return jsonify({'error': 'Branch admin cannot manage other admins or super admins'}), 403

    update_fields = []
    update_values = []
    if username is not None:
        update_fields.append("username = ?")
        update_values.append(username)
    if password is not None:
        update_fields.append("password_hash = ?")
        update_values.append(generate_password_hash(password))
    if role is not None:
        update_fields.append("role = ?")
        update_values.append(role)
    if 'telegram_user_id' in data: # Allows setting to NULL
        update_fields.append("telegram_user_id = ?")
        update_values.append(telegram_user_id)
    if is_vip is not None:
        update_fields.append("is_vip = ?")
        update_values.append(bool(is_vip))
    if loyalty_points is not None:
        update_fields.append("loyalty_points = ?")
        update_values.append(int(loyalty_points))
    if is_available is not None:
        update_fields.append("is_available = ?")
        update_values.append(bool(is_available))
    if available_start_time is not None:
        update_fields.append("available_start_time = ?")
        update_values.append(available_start_time)
    if available_end_time is not None:
        update_fields.append("available_end_time = ?")
        update_values.append(available_end_time)

    if not update_fields:
        # conn.close()
        logging.info(f"User {current_user['username']} attempted to update user {user_id} with no changes.")
        return jsonify({'message': 'No fields to update'}), 200

    update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
    update_values.append(user_id)

    try:
        conn.execute(update_query, tuple(update_values))
        conn.commit()
        if conn.changes() == 0:
            logging.warning(f"User {current_user['username']} failed to update user {user_id} (not found or no changes).")
            return jsonify({"error": "User not found or no changes made"}), 404
        logging.info(f"User {current_user['username']} updated user ID {user_id}.")
        return jsonify({'message': 'User updated successfully'}), 200
    except sqlite3.IntegrityError:
        conn.rollback()
        logging.warning(f"User {current_user['username']} attempted to update user {user_id} with duplicate username or Telegram user ID.")
        return jsonify({'error': 'Username or Telegram user ID already exists for this branch/globally'}), 409
    except Exception as e:
        conn.rollback()
        logging.error(f"User {current_user['username']} failed to update user {user_id}: {e}")
        return jsonify({'error': 'Failed to update user'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/delete_user/<int:user_id>', methods=['DELETE'])
@login_required(role='branch_admin') # Super admin can delete all users too
def delete_user(user_id, current_user):
    """Deletes a user from a specific branch."""
    conn = get_db()
    user_to_delete = conn.execute("SELECT branch_id, role FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user_to_delete:
        # conn.close()
        logging.warning(f"User {current_user['username']} attempted to delete non-existent user ID: {user_id}.")
        return jsonify({'error': 'User not found'}), 404

    if current_user['role'] == 'branch_admin':
        if user_to_delete['branch_id'] != current_user['branch_id']:
            # conn.close()
            logging.warning(f"Branch admin {current_user['username']} attempted to delete user {user_id} from another branch.")
            return jsonify({'error': 'Branch admin cannot delete users from other branches'}), 403
        if user_to_delete['role'] in ['super_admin', 'branch_admin']:
            # conn.close()
            logging.warning(f"Branch admin {current_user['username']} attempted to delete an admin user {user_id}.")
            return jsonify({'error': 'Branch admin cannot delete super admins or other branch admins'}), 403
    elif current_user['role'] == 'super_admin':
        if user_id == current_user['user_id']:
            # conn.close()
            logging.warning(f"Super admin {current_user['username']} attempted to delete their own account.")
            return jsonify({'error': 'Super admin cannot delete their own account'}), 403

    try:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        if conn.changes() == 0:
            logging.warning(f"User {current_user['username']} failed to delete user {user_id} (not found or no changes).")
            return jsonify({'error': 'User not found or no changes made'}), 404
        logging.info(f"User {current_user['username']} deleted user ID {user_id}.")
        return jsonify({'message': 'User deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"User {current_user['username']} failed to delete user {user_id}: {e}")
        return jsonify({'error': 'Failed to delete user'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

# --- Public API endpoints for kiosk/client app ---
@app.route('/api/public_categories/<int:branch_id>', methods=['GET'])
def get_public_categories(branch_id):
    """Returns active categories for the public display, filtered by branch."""
    conn = get_db()
    categories = conn.execute("""
        SELECT id, name_uz_lat, name_uz_cyr, name_ru, name_en, description_uz_lat, description_uz_cyr, description_ru, description_en, parent_id, has_operators
        FROM categories
        WHERE branch_id = ?
    """, (branch_id,)).fetchall()
    # conn.close()
    logging.debug(f"Fetched public categories for branch {branch_id}.")
    return jsonify([dict(row) for row in categories])

@app.route('/api/public_services/<int:category_id>', methods=['GET'])
def get_public_services(category_id):
    """Returns active services for a given category for public display."""
    conn = get_db()
    services = conn.execute("""
        SELECT s.id, s.name_uz_lat, s.name_uz_cyr, s.name_ru, s.name_en, s.description_uz_lat, s.category_id
        FROM services s
        WHERE s.category_id = ? AND s.is_active = 1
    """, (category_id,)).fetchall()
    # conn.close()
    logging.debug(f"Fetched public services for category {category_id}.")
    return jsonify([dict(row) for row in services])

@app.route('/api/issue_ticket', methods=['POST'])
def issue_ticket_api():
    """API to issue a new ticket via the kiosk/client app."""
    data = request.json
    service_id = data.get('service_id')
    branch_id = data.get('branch_id')
    client_telegram_user_id = data.get('client_telegram_user_id') # Can be None if not from Telegram

    if not all([service_id, branch_id]):
        logging.error("Attempted to issue ticket with missing service_id or branch_id.")
        return jsonify({'error': 'Service ID and Branch ID are required'}), 400

    conn = get_db()
    service = conn.execute("SELECT id, name_uz_lat FROM services WHERE id = ? AND branch_id = ? AND is_active = 1",
                           (service_id, branch_id)).fetchone()
    if not service:
        # conn.close()
        logging.error(f"Attempted to issue ticket for non-existent or inactive service {service_id} in branch {branch_id}.")
        return jsonify({'error': 'Service not found or inactive in this branch'}), 404

    try:
        today_str = datetime.now().strftime("%Y-%m-%d")
        c = conn.cursor()
        c.execute("""
            SELECT COUNT(*) FROM tickets
            WHERE branch_id = ? AND DATE(start_time) = DATE(?)
        """, (branch_id, today_str))
        ticket_count_today = c.fetchone()[0]

        # Generating ticket number
        ticket_number = f"BR{branch_id}-{ticket_count_today + 1:03d}"
        ticket_uuid = str(uuid.uuid4())

        c.execute("""
            INSERT INTO tickets (id, number, service_id, client_telegram_user_id, status, branch_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ticket_uuid, ticket_number, service_id, client_telegram_user_id, 'waiting', branch_id))

        if client_telegram_user_id:
            # Update the client's current_ticket_id in the users table and add loyalty points
            c.execute("UPDATE users SET current_ticket_id = ?, loyalty_points = loyalty_points + 1 WHERE telegram_user_id = ?",
                      (ticket_uuid, client_telegram_user_id))
        conn.commit()

        # Generate QR code
        qr_data = url_for('chat_page', ticket_id=ticket_uuid, _external=True, _scheme='http' if FLASK_EXTERNAL_URL is None else None)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        qr_filename = f"{ticket_uuid}.png"
        qr_filepath = os.path.join(QR_CODE_FOLDER, qr_filename)
        img.save(qr_filepath)

        c.execute("UPDATE tickets SET qr_code_path = ? WHERE id = ?", (qr_filepath, ticket_uuid))
        conn.commit()

        ticket_info = {
            'ticket_id': ticket_uuid,
            'number': ticket_number,
            'service_name': service['name_uz_lat'],
            'qr_code_url': url_for('serve_qr_code', filename=qr_filename, _external=True),
            'status': 'waiting',
            'branch_id': branch_id
        }

        # Emit real-time updates via SocketIO
        socketio.emit('new_ticket', ticket_info, room=f'display_{branch_id}')
        socketio.emit('new_ticket', ticket_info, room=f'operator_branch_{branch_id}')

        logging.info(f"New ticket issued: {ticket_number} (Service ID: {service_id}, Branch: {branch_id}).")
        return jsonify(ticket_info), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Error issuing ticket for service {service_id} in branch {branch_id}: {e}")
        return jsonify({'error': 'Failed to issue ticket'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/qrcode/<filename>')
def serve_qr_code(filename):
    """Serves generated QR code images."""
    try:
        return send_file(os.path.join(QR_CODE_FOLDER, filename), mimetype='image/png')
    except FileNotFoundError:
        logging.error(f"QR code file not found: {filename}")
        abort(404)


@app.route('/api/get_queue/<int:branch_id>', methods=['GET'])
def get_queue_api(branch_id):
    """Returns the current queue for a specific branch."""
    conn = get_db()
    # Updated ORDER BY to prioritize VIP clients and then sort_order
    queue = conn.execute("""
        SELECT t.id, t.number, s.name_uz_lat as service_name, t.status, op.username as operator_username,
               CASE WHEN u.is_vip = 1 THEN 0 ELSE 1 END AS vip_order -- VIPs first
        FROM tickets t
        JOIN services s ON t.service_id = s.id
        LEFT JOIN users op ON t.operator_id = op.id
        LEFT JOIN users u ON t.client_telegram_user_id = u.telegram_user_id
        WHERE t.branch_id = ? AND t.status IN ('waiting', 'called')
        ORDER BY vip_order ASC, t.sort_order ASC NULLS LAST, t.start_time ASC
    """, (branch_id,)).fetchall()
    # conn.close()
    logging.debug(f"Fetched queue for branch {branch_id}.")
    return jsonify([dict(row) for row in queue])

# --- Operator Specific APIs ---
@app.route('/api/operator/my_tickets', methods=['GET'])
@login_required(role='operator')
def get_operator_tickets(current_user):
    """Returns tickets assigned to the logged-in operator for their branch."""
    operator_id = current_user['id']
    branch_id = current_user['branch_id']

    conn = get_db()
    tickets = conn.execute("""
        SELECT t.id, t.number, s.name_uz_lat as service_name, t.status, t.start_time, t.call_time, t.finish_time,
               t.client_telegram_user_id, t.qr_code_path
        FROM tickets t
        JOIN services s ON t.service_id = s.id
        LEFT JOIN users op_assigned ON s.operator_id = op_assigned.id -- operator assigned to service
        LEFT JOIN users op_called ON t.operator_id = op_called.id -- operator who called the ticket
        WHERE t.branch_id = ?
              AND (op_assigned.id = ? OR op_called.id = ?) -- Check if service has this operator assigned or ticket was called by this operator
              AND t.status IN ('waiting', 'called', 'redirected')
        ORDER BY t.status DESC, t.start_time ASC
    """, (branch_id, operator_id, operator_id)).fetchall()
    # conn.close()
    logging.debug(f"Operator {current_user['username']} fetched their tickets for branch {branch_id}.")
    return jsonify([dict(row) for row in tickets])


@app.route('/api/operator/call_next', methods=['POST'])
@login_required(role='operator')
def call_next_ticket_api(current_user):
    """Calls the next available ticket for the logged-in operator's branch."""
    operator_id = current_user['id']
    branch_id = current_user['branch_id']

    conn = get_db()
    c = conn.cursor()

    # Get operator availability
    operator_info = c.execute("SELECT is_available, available_start_time, available_end_time FROM users WHERE id = ?", (operator_id,)).fetchone()
    if not operator_info or not operator_info['is_available']:
        logging.warning(f"Operator {current_user['username']} attempted to call next ticket but is marked as unavailable.")
        return jsonify({'message': 'You are currently not available to take tickets.'}), 400

    current_time = datetime.now()
    if operator_info['available_start_time'] and current_time < datetime.fromisoformat(operator_info['available_start_time']):
        logging.warning(f"Operator {current_user['username']} attempted to call next ticket before their available start time.")
        return jsonify({'message': 'You are not yet in your available time slot.'}), 400
    if operator_info['available_end_time'] and current_time > datetime.fromisoformat(operator_info['available_end_time']):
        logging.warning(f"Operator {current_user['username']} attempted to call next ticket after their available end time.")
        return jsonify({'message': 'Your available time slot has ended.'}), 400

    # Prioritize VIPs and then sort_order for next ticket
    ticket_to_call = c.execute("""
        SELECT t.id, t.number, s.name_uz_lat as service_name, t.client_telegram_user_id
        FROM tickets t
        JOIN services s ON t.service_id = s.id
        LEFT JOIN users op_assigned ON s.operator_id = op_assigned.id
        LEFT JOIN users client_user ON t.client_telegram_user_id = client_user.telegram_user_id
        WHERE t.branch_id = ?
              AND t.status IN ('waiting', 'redirected')
              AND (op_assigned.id = ? OR op_assigned.id IS NULL) -- Assigned to this operator or unassigned
        ORDER BY CASE WHEN client_user.is_vip = 1 THEN 0 ELSE 1 END ASC,
                 t.sort_order ASC NULLS LAST, t.start_time ASC
        LIMIT 1
    """, (branch_id, operator_id)).fetchone()


    if not ticket_to_call:
        # conn.close()
        logging.info(f"Operator {current_user['username']} attempted to call next ticket but none were available in branch {branch_id}.")
        return jsonify({'message': 'No waiting tickets available for you'}), 404

    try:
        c.execute("UPDATE tickets SET status = 'called', operator_id = ?, call_time = CURRENT_TIMESTAMP WHERE id = ?",
                     (operator_id, ticket_to_call['id']))
        conn.commit()

        updated_ticket = c.execute("""
            SELECT t.id, t.number, t.status, t.call_time, u.username as operator_username,
                   s.name_uz_lat as service_name_uz_lat, t.client_telegram_user_id
            FROM tickets t
            JOIN services s ON t.service_id = s.id
            LEFT JOIN users u ON t.operator_id = u.id
            WHERE t.id = ?
        """, (ticket_to_call['id'],)).fetchone()
        # conn.close()

        ticket_data_to_emit = {
            'id': updated_ticket['id'],
            'number': updated_ticket['number'],
            'service_name': updated_ticket['service_name_uz_lat'],
            'status': updated_ticket['status'],
            'operator_username': updated_ticket['operator_username'],
            'branch_id': branch_id
        }

        socketio.emit('ticket_called', ticket_data_to_emit, room=f'display_{branch_id}')
        socketio.emit('ticket_called', ticket_data_to_emit, room=f'operator_{operator_id}_{branch_id}') # Emit to operator's specific room
        socketio.emit('ticket_called', ticket_data_to_emit, room=f'operator_branch_{branch_id}') # Emit to general operator dashboard
        logging.info(f"Ticket called by operator {current_user['username']}: {updated_ticket['number']} (Branch: {branch_id}).")

        if bot and updated_ticket['client_telegram_user_id']:
            client_tg_id = updated_ticket['client_telegram_user_id']
            try:
                # Get the client's preferred language from the 'users' table
                client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
                client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

                message_text = get_text(client_lang, 'your_ticket_info',
                                        ticket_number=updated_ticket['number'],
                                        service_name=updated_ticket['service_name_uz_lat'],
                                        status=get_text(client_lang, 'status_called'))
                message_text += get_text(client_lang, 'operator_info', operator_username=updated_ticket['operator_username'])

                asyncio.run_coroutine_threadsafe(
                    bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                    dp.loop
                )
                logging.info(f"Telegram notification sent to client {client_tg_id} for ticket {updated_ticket['number']}.")
            except Exception as e:
                logging.error(f"Failed to send Telegram notification to client {client_tg_id}: {e}")

        return jsonify({'message': 'Ticket called', 'ticket': dict(updated_ticket)}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Operator {current_user['username']} failed to call next ticket in branch {branch_id}: {e}")
        return jsonify({'error': 'Failed to call ticket'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()


@app.route('/api/operator/finish_ticket/<string:ticket_id>', methods=['POST'])
@login_required(role='operator')
def finish_ticket_api(ticket_id, current_user):
    """Finishes a ticket that was called by the logged-in operator."""
    operator_id = current_user['id']
    branch_id = current_user['branch_id']

    conn = get_db()
    c = conn.cursor()

    ticket_check = c.execute("SELECT id, client_telegram_user_id FROM tickets WHERE id = ? AND operator_id = ? AND branch_id = ? AND status = 'called'",
                             (ticket_id, operator_id, branch_id)).fetchone()
    if not ticket_check:
        # conn.close()
        logging.warning(f"Operator {current_user['username']} attempted to finish ticket {ticket_id} which was not called by them or not in 'called' status.")
        return jsonify({'error': 'Ticket not found, not called by you, or not in "called" status'}), 404

    client_tg_id = ticket_check['client_telegram_user_id']

    try:
        c.execute("UPDATE tickets SET status = 'finished', finish_time = CURRENT_TIMESTAMP WHERE id = ?", (ticket_id,))
        if client_tg_id:
            c.execute("UPDATE users SET current_ticket_id = NULL WHERE telegram_user_id = ? AND current_ticket_id = ?",
                      (client_tg_id, ticket_id))
        conn.commit()
        # conn.close() # Managed by teardown_appcontext

        socketio.emit('ticket_finished', {'ticket_id': ticket_id, 'status': 'finished', 'branch_id': branch_id}, room=f'display_{branch_id}')
        socketio.emit('ticket_finished', {'ticket_id': ticket_id, 'status': 'finished', 'branch_id': branch_id}, room=f'operator_{operator_id}_{branch_id}')
        socketio.emit('ticket_finished', {'ticket_id': ticket_id, 'status': 'finished', 'branch_id': branch_id}, room=f'operator_branch_{branch_id}')
        logging.info(f"Ticket {ticket_id} finished by operator {current_user['username']} (Branch: {branch_id}).")

        # Send Telegram notification to client about feedback/dispute
        base_url = FLASK_EXTERNAL_URL if FLASK_EXTERNAL_URL else f"http://{FLASK_RUN_HOST}:{FLASK_RUN_PORT}"
        if bot and client_tg_id:
            # Get the client's preferred language from the 'users' table
            client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
            client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

            feedback_url = f"{base_url}/feedback/{ticket_id}"
            dispute_url = f"{base_url}/dispute/{ticket_id}"
            message_text = get_text(client_lang, 'ticket_finished_msg', ticket_id=ticket_id) + "\n" + \
                           get_text(client_lang, 'give_feedback_btn') + f": {feedback_url}\n" + \
                           get_text(client_lang, 'file_dispute_btn') + f": {dispute_url}"
            try:
                asyncio.run_coroutine_threadsafe(
                    bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                    dp.loop
                )
                logging.info(f"Telegram feedback/dispute prompt sent to client {client_tg_id} for ticket {ticket_id}.")
            except Exception as e:
                logging.error(f"Failed to send Telegram feedback/dispute prompt to client {client_tg_id}: {e}")
        elif bot and client_tg_id and not FLASK_EXTERNAL_URL:
            # Get the client's preferred language from the 'users' table
            client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
            client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

            message_text = get_text(client_lang, 'ticket_finished_msg', ticket_id=ticket_id)
            try:
                asyncio.run_coroutine_threadsafe(
                    bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                    dp.loop
                )
                logging.info(f"Telegram finished notification sent to client {client_tg_id} for ticket {ticket_id} (no external links).")
            except Exception as e:
                logging.error(f"Failed to send basic Telegram finished notification to client {client_tg_id}: {e}")

        return jsonify({'message': 'Ticket finished successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Operator {current_user['username']} failed to finish ticket {ticket_id}: {e}")
        return jsonify({'error': 'Failed to finish ticket'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/operator/redirect_ticket/<string:ticket_id>', methods=['POST'])
@login_required(role='operator')
def redirect_ticket_api(ticket_id, current_user):
    """Redirects a ticket to another service/operator within the same branch."""
    operator_id = current_user['id']
    branch_id = current_user['branch_id']
    data = request.json
    new_service_id = data.get('new_service_id')

    if not new_service_id:
        logging.error(f"Operator {current_user['username']} attempted to redirect ticket {ticket_id} without new service ID.")
        return jsonify({'error': 'New service ID is required'}), 400

    conn = get_db()
    c = conn.cursor()

    ticket_check = c.execute("SELECT id, client_telegram_user_id FROM tickets WHERE id = ? AND operator_id = ? AND branch_id = ? AND status = 'called'",
                             (ticket_id, operator_id, branch_id)).fetchone()
    if not ticket_check:
        # conn.close()
        logging.warning(f"Operator {current_user['username']} attempted to redirect ticket {ticket_id} which was not called by them or not in 'called' status.")
        return jsonify({'error': 'Ticket not found, not called by you, or not in "called" status'}), 404

    client_tg_id = ticket_check['client_telegram_user_id']

    new_service = c.execute("SELECT name_uz_lat FROM services WHERE id = ? AND branch_id = ?", (new_service_id, branch_id)).fetchone()
    if not new_service:
        # conn.close()
        logging.warning(f"Operator {current_user['username']} attempted to redirect ticket {ticket_id} to non-existent new service {new_service_id}.")
        return jsonify({'error': 'New service not found or not in your branch'}), 404

    try:
        c.execute("""
            UPDATE tickets SET status = 'waiting', service_id = ?, redirect_to_service_id = ?,
            operator_id = NULL, redirect_time = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (new_service_id, new_service_id, ticket_id))
        conn.commit()
        # conn.close() # Managed by teardown_appcontext

        socketio.emit('ticket_redirected', {
            'ticket_id': ticket_id,
            'new_service_id': new_service_id,
            'new_service_name': new_service['name_uz_lat'],
            'branch_id': branch_id
        }, room=f'display_{branch_id}')
        socketio.emit('ticket_redirected', {
            'ticket_id': ticket_id,
            'new_service_id': new_service_id,
            'new_service_name': new_service['name_uz_lat'],
            'branch_id': branch_id
        }, room=f'operator_{operator_id}_{branch_id}')
        socketio.emit('ticket_redirected', {
            'ticket_id': ticket_id,
            'new_service_id': new_service_id,
            'new_service_name': new_service['name_uz_lat'],
            'branch_id': branch_id
        }, room=f'operator_branch_{branch_id}')
        logging.info(f"Ticket {ticket_id} redirected by operator {current_user['username']} to service {new_service_id} (Branch: {branch_id}).")

        if bot and client_tg_id:
            # Get the client's preferred language from the 'users' table
            client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
            client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

            message_text = get_text(client_lang, 'ticket_redirected_msg',
                                    ticket_id=ticket_id,
                                    new_service_name=new_service['name_uz_lat'])
            try:
                asyncio.run_coroutine_threadsafe(
                    bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                    dp.loop
                )
                logging.info(f"Telegram redirect notification sent to client {client_tg_id} for ticket {ticket_id}.")
            except Exception as e:
                logging.error(f"Failed to send Telegram redirect notification to client {client_tg_id}: {e}")

        return jsonify({'message': 'Ticket redirected successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Operator {current_user['username']} failed to redirect ticket {ticket_id}: {e}")
        return jsonify({'error': 'Failed to redirect ticket'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/operator/cancel_ticket/<string:ticket_id>', methods=['POST'])
@login_required(role='operator')
def cancel_ticket_api(ticket_id, current_user):
    """Cancels a ticket that was called by the logged-in operator."""
    operator_id = current_user['id']
    branch_id = current_user['branch_id']

    conn = get_db()
    c = conn.cursor()

    ticket_check = c.execute("SELECT id, client_telegram_user_id FROM tickets WHERE id = ? AND operator_id = ? AND branch_id = ? AND status = 'called'",
                             (ticket_id, operator_id, branch_id)).fetchone()
    if not ticket_check:
        # conn.close()
        logging.warning(f"Operator {current_user['username']} attempted to cancel ticket {ticket_id} which was not called by them or not in 'called' status.")
        return jsonify({'error': 'Ticket not found, not called by you, or not in "called" status'}), 404

    client_tg_id = ticket_check['client_telegram_user_id']

    try:
        c.execute("UPDATE tickets SET status = 'cancelled', finish_time = CURRENT_TIMESTAMP WHERE id = ?", (ticket_id,))
        if client_tg_id:
            c.execute("UPDATE users SET current_ticket_id = NULL WHERE telegram_user_id = ? AND current_ticket_id = ?",
                      (client_tg_id, ticket_id))
        conn.commit()
        # conn.close() # Managed by teardown_appcontext

        socketio.emit('ticket_cancelled', {'ticket_id': ticket_id, 'status': 'cancelled', 'branch_id': branch_id}, room=f'display_{branch_id}')
        socketio.emit('ticket_cancelled', {'ticket_id': ticket_id, 'status': 'cancelled', 'branch_id': branch_id}, room=f'operator_{operator_id}_{branch_id}')
        socketio.emit('ticket_cancelled', {'ticket_id': ticket_id, 'status': 'cancelled', 'branch_id': branch_id}, room=f'operator_branch_{branch_id}')
        logging.info(f"Ticket {ticket_id} cancelled by operator {current_user['username']} (Branch: {branch_id}).")

        if bot and client_tg_id:
            # Get the client's preferred language from the 'users' table
            client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
            client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

            message_text = get_text(client_lang, 'ticket_cancelled_msg', ticket_id=ticket_id)
            try:
                asyncio.run_coroutine_threadsafe(
                    bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                    dp.loop
                )
                logging.info(f"Telegram cancellation notification sent to client {client_tg_id} for ticket {ticket_id}.")
            except Exception as e:
                logging.error(f"Failed to send Telegram cancellation notification to client {client_tg_id}: {e}")

        return jsonify({'message': 'Ticket cancelled successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Operator {current_user['username']} failed to cancel ticket {ticket_id}: {e}")
        return jsonify({'error': 'Failed to cancel ticket'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/operator/no_show_ticket/<string:ticket_id>', methods=['POST'])
@login_required(role='operator')
def no_show_ticket_api(ticket_id, current_user):
    """Marks a called ticket as 'no_show'."""
    operator_id = current_user['id']
    branch_id = current_user['branch_id']

    conn = get_db()
    c = conn.cursor()

    ticket_check = c.execute("SELECT id, client_telegram_user_id FROM tickets WHERE id = ? AND operator_id = ? AND branch_id = ? AND status = 'called'",
                             (ticket_id, operator_id, branch_id)).fetchone()
    if not ticket_check:
        # conn.close()
        logging.warning(f"Operator {current_user['username']} attempted to mark ticket {ticket_id} as no-show which was not called by them or not in 'called' status.")
        return jsonify({'error': 'Ticket not found, not called by you, or not in "called" status'}), 404

    client_tg_id = ticket_check['client_telegram_user_id']

    try:
        c.execute("UPDATE tickets SET status = 'no_show', finish_time = CURRENT_TIMESTAMP WHERE id = ?", (ticket_id,))
        if client_tg_id:
            c.execute("UPDATE users SET current_ticket_id = NULL WHERE telegram_user_id = ? AND current_ticket_id = ?",
                      (client_tg_id, ticket_id))
        conn.commit()
        # conn.close() # Managed by teardown_appcontext

        socketio.emit('ticket_no_show', {'ticket_id': ticket_id, 'status': 'no_show', 'branch_id': branch_id}, room=f'display_{branch_id}')
        socketio.emit('ticket_no_show', {'ticket_id': ticket_id, 'status': 'no_show', 'branch_id': branch_id}, room=f'operator_{operator_id}_{branch_id}')
        socketio.emit('ticket_no_show', {'ticket_id': ticket_id, 'status': 'no_show', 'branch_id': branch_id}, room=f'operator_branch_{branch_id}')
        logging.info(f"Ticket {ticket_id} marked as no-show by operator {current_user['username']} (Branch: {branch_id}).")

        if bot and client_tg_id:
            # Get the client's preferred language from the 'users' table
            client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
            client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

            message_text = get_text(client_lang, 'ticket_no_show_msg', ticket_id=ticket_id)
            try:
                asyncio.run_coroutine_threadsafe(
                    bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                    dp.loop
                )
                logging.info(f"Telegram no-show notification sent to client {client_tg_id} for ticket {ticket_id}.")
            except Exception as e:
                logging.error(f"Failed to send Telegram no-show notification to client {client_tg_id}: {e}")

        return jsonify({'message': 'Ticket marked as no-show successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Operator {current_user['username']} failed to mark ticket {ticket_id} as no-show: {e}")
        return jsonify({'error': 'Failed to mark ticket as no-show'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/operator/skip_ticket/<string:ticket_id>', methods=['POST'])
@login_required(role='operator')
def skip_ticket_api(ticket_id, current_user):
    """Marks a called ticket as 'skipped'."""
    operator_id = current_user['id']
    branch_id = current_user['branch_id']

    conn = get_db()
    c = conn.cursor()

    ticket_check = c.execute("SELECT id, client_telegram_user_id FROM tickets WHERE id = ? AND operator_id = ? AND branch_id = ? AND status = 'called'",
                             (ticket_id, operator_id, branch_id)).fetchone()
    if not ticket_check:
        # conn.close()
        logging.warning(f"Operator {current_user['username']} attempted to skip ticket {ticket_id} which was not called by them or not in 'called' status.")
        return jsonify({'error': 'Ticket not found, not called by you, or not in "called" status'}), 404

    client_tg_id = ticket_check['client_telegram_user_id']

    try:
        c.execute("UPDATE tickets SET status = 'waiting', operator_id = NULL WHERE id = ?", (ticket_id,))
        # Do NOT clear current_ticket_id for skipped tickets, as they are still in queue.
        conn.commit()
        # conn.close() # Managed by teardown_appcontext

        socketio.emit('ticket_skipped', {'ticket_id': ticket_id, 'status': 'waiting', 'branch_id': branch_id}, room=f'display_{branch_id}')
        socketio.emit('ticket_skipped', {'ticket_id': ticket_id, 'status': 'waiting', 'branch_id': branch_id}, room=f'operator_{operator_id}_{branch_id}')
        socketio.emit('ticket_skipped', {'ticket_id': ticket_id, 'status': 'waiting', 'branch_id': branch_id}, room=f'operator_branch_{branch_id}')
        logging.info(f"Ticket {ticket_id} skipped by operator {current_user['username']} (Branch: {branch_id}).")

        if bot and client_tg_id:
            # Get the client's preferred language from the 'users' table
            client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
            client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

            message_text = get_text(client_lang, 'ticket_skipped_msg', ticket_id=ticket_id)
            try:
                asyncio.run_coroutine_threadsafe(
                    bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                    dp.loop
                )
                logging.info(f"Telegram skipped notification sent to client {client_tg_id} for ticket {ticket_id}.")
            except Exception as e:
                logging.error(f"Failed to send Telegram skipped notification to client {client_tg_id}: {e}")

        return jsonify({'message': 'Ticket skipped successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Operator {current_user['username']} failed to skip ticket {ticket_id}: {e}")
        return jsonify({'error': 'Failed to skip ticket'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/operator_stats', methods=['GET'])
@login_required(role='operator')
def get_operator_stats(current_user):
    """Returns daily statistics for the logged-in operator."""
    operator_id = current_user['id']
    branch_id = current_user['branch_id']

    conn = get_db()
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)

    tickets_finished = conn.execute("""
        SELECT COUNT(*) FROM tickets
        WHERE operator_id = ? AND branch_id = ? AND status = 'finished'
        AND finish_time BETWEEN ? AND ?
    """, (operator_id, branch_id, today_start, today_end)).fetchone()[0]

    avg_service_time = conn.execute("""
        SELECT AVG(strftime('%s', finish_time) - strftime('%s', call_time)) FROM tickets
        WHERE operator_id = ? AND branch_id = ? AND status = 'finished'
        AND finish_time BETWEEN ? AND ?
    """, (operator_id, branch_id, today_start, today_end)).fetchone()[0]

    # Feedback and disputes related to tickets handled by this operator
    feedback_count = conn.execute("""
        SELECT COUNT(f.id) FROM feedback f
        JOIN tickets t ON f.ticket_id = t.id
        WHERE t.operator_id = ? AND t.branch_id = ?
    """, (operator_id, branch_id)).fetchone()[0]

    avg_rating = conn.execute("""
        SELECT AVG(f.rating) FROM feedback f
        JOIN tickets t ON f.ticket_id = t.id
        WHERE t.operator_id = ? AND t.branch_id = ?
    """, (operator_id, branch_id)).fetchone()[0]

    dispute_count = conn.execute("""
        SELECT COUNT(d.id) FROM disputes d
        JOIN tickets t ON d.ticket_id = t.id
        WHERE t.operator_id = ? AND t.branch_id = ?
    """, (operator_id, branch_id)).fetchone()[0]

    # conn.close() # Managed by teardown_appcontext
    logging.debug(f"Operator {current_user['username']} fetched daily stats for branch {branch_id}.")

    return jsonify({
        "tickets_finished_today": tickets_finished,
        "avg_service_time_today_seconds": int(avg_service_time) if avg_service_time else 0,
        "feedback_count": feedback_count,
        "avg_rating": round(avg_rating, 2) if avg_rating else "N/A",
        "dispute_count": dispute_count
    })

# --- Admin Analytics API ---
@app.route('/api/admin_analytics/<int:branch_id>', methods=['GET'])
@login_required(role='branch_admin')
def admin_analytics(branch_id, current_user):
    """Returns daily analytics for a specific branch."""
    date_str = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    try:
        selected_date = datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        logging.error(f"Admin {current_user['username']} provided invalid date format: {date_str}.")
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

    start_of_day = selected_date.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = start_of_day + timedelta(days=1)

    conn = get_db()

    total_tickets = conn.execute("SELECT COUNT(*) FROM tickets WHERE branch_id = ? AND start_time BETWEEN ? AND ?",
                                 (branch_id, start_of_day, end_of_day)).fetchone()[0]

    tickets_by_status = conn.execute("""
        SELECT status, COUNT(*) as count FROM tickets
        WHERE branch_id = ? AND start_time BETWEEN ? AND ?
        GROUP BY status
    """, (branch_id, start_of_day, end_of_day)).fetchall()

    service_popularity = conn.execute("""
        SELECT s.name_uz_lat, COUNT(t.id) as count,
               AVG(strftime('%s', t.finish_time) - strftime('%s', t.call_time)) as avg_service_time_seconds
        FROM tickets t
        JOIN services s ON t.service_id = s.id
        WHERE t.branch_id = ? AND t.status = 'finished' AND t.start_time BETWEEN ? AND ?
        GROUP BY s.id
        ORDER BY count DESC
        LIMIT 5
    """, (branch_id, start_of_day, end_of_day)).fetchall()

    operator_performance = conn.execute("""
        SELECT u.username, COUNT(t.id) as tickets_finished,
               AVG(strftime('%s', t.finish_time) - strftime('%s', t.call_time)) as avg_service_time_seconds
        FROM tickets t
        JOIN users u ON t.operator_id = u.id
        WHERE t.branch_id = ? AND t.status = 'finished' AND t.finish_time BETWEEN ? AND ?
        GROUP BY u.id
        ORDER BY tickets_finished DESC
    """, (branch_id, start_of_day, end_of_day)).fetchall()

    total_feedback = conn.execute("""
        SELECT COUNT(*) FROM feedback f
        JOIN tickets t ON f.ticket_id = t.id
        WHERE t.branch_id = ? AND f.timestamp BETWEEN ? AND ?
    """, (branch_id, start_of_day, end_of_day)).fetchone()[0]

    avg_overall_rating = conn.execute("""
        SELECT AVG(f.rating) FROM feedback f
        JOIN tickets t ON f.ticket_id = t.id
        WHERE t.branch_id = ? AND f.timestamp BETWEEN ? AND ?
    """, (branch_id, start_of_day, end_of_day)).fetchone()[0]

    total_disputes = conn.execute("""
        SELECT COUNT(*) FROM disputes d
        JOIN tickets t ON d.ticket_id = t.id
        WHERE t.branch_id = ? AND d.timestamp BETWEEN ? AND ?
    """, (branch_id, start_of_day, end_of_day)).fetchone()[0]

    # conn.close() # Managed by teardown_appcontext
    logging.info(f"Branch admin {current_user['username']} fetched analytics for branch {branch_id} on {date_str}.")

    return jsonify({
        "date": date_str,
        "total_tickets_generated": total_tickets,
        "tickets_by_status": [dict(row) for row in tickets_by_status],
        "service_popularity": [dict(row) for row in service_popularity],
        "operator_performance": [dict(row) for row in operator_performance],
        "total_feedback": total_feedback,
        "avg_overall_rating": round(avg_overall_rating, 2) if avg_overall_rating else "N/A",
        "total_disputes": total_disputes
    })

# --- Chat API ---
@app.route('/api/chat/history/<string:ticket_id>', methods=['GET'])
def get_chat_history(ticket_id):
    """Returns chat history for a specific ticket."""
    conn = get_db()
    messages = conn.execute("""
        SELECT cm.message, cm.sender_type, cm.timestamp, u.username as operator_username
        FROM chat_messages cm
        LEFT JOIN users u ON cm.sender_id = u.id
        WHERE cm.ticket_id = ?
        ORDER BY cm.timestamp ASC
    """, (ticket_id,)).fetchall()
    # conn.close()
    logging.debug(f"Fetched chat history for ticket {ticket_id}.")
    return jsonify([dict(row) for row in messages])

@socketio.on('send_message')
def handle_send_message(data):
    """Handles new chat messages received via SocketIO."""
    ticket_id = data.get('ticket_id')
    sender_type = data.get('sender_type')
    message = data.get('message')
    user_id = data.get('user_id') # This is user.id for operators, telegram_user_id for clients (might need adjustment)
    branch_id = data.get('branch_id')

    if not all([ticket_id, sender_type, message, branch_id]):
        logging.error(f"Missing data for send_message SocketIO event: {data}")
        emit('message_error', {'error': 'Missing data'})
        return

    conn = get_db()
    try:
        sender_db_id = None
        if sender_type == 'operator':
            # For operators, user_id from session is their primary key
            sender_db_id = user_id
        elif sender_type == 'client':
            # For clients, user_id is telegram_user_id, find their internal DB id
            client_user_row = conn.execute("SELECT id FROM users WHERE telegram_user_id = ?", (user_id,)).fetchone()
            if client_user_row:
                sender_db_id = client_user_row['id']

        if sender_db_id is None:
            logging.error(f"Could not determine sender_id for message: {data}")
            emit('message_error', {'error': 'Invalid sender information'})
            return

        c = conn.cursor()
        c.execute("""
            INSERT INTO chat_messages (ticket_id, sender_id, sender_type, message, branch_id)
            VALUES (?, ?, ?, ?, ?)
        """, (ticket_id, sender_db_id, sender_type, message, branch_id))
        conn.commit()

        sender_username = None
        # Retrieve sender's username for display
        user_row = conn.execute("SELECT username FROM users WHERE id = ?", (sender_db_id,)).fetchone()
        if user_row:
            sender_username = user_row['username']

        message_data = {
            'ticket_id': ticket_id,
            'sender_type': sender_type,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'operator_username': sender_username, # Will be None if sender_type is 'client'
            'branch_id': branch_id
        }

        # Emit to the specific ticket chat room (for clients and operators viewing this chat)
        socketio.emit('new_message', message_data, room=f'ticket_{ticket_id}')

        # Also notify relevant operators
        if sender_type == 'client':
            ticket_info = conn.execute("SELECT operator_id FROM tickets WHERE id = ? AND branch_id = ?", (ticket_id, branch_id)).fetchone()
            if ticket_info and ticket_info['operator_id']:
                operator_room = f'operator_{ticket_info["operator_id"]}_{branch_id}'
                socketio.emit('new_chat_message_for_operator', message_data, room=operator_room)
            # Notify general operator dashboard for the branch
            socketio.emit('new_chat_message_for_operator', message_data, room=f'operator_branch_{branch_id}')

        logging.info(f"New chat message: Ticket ID {ticket_id}, Sender: {sender_type}, Branch: {branch_id}")

    except Exception as e:
        conn.rollback()
        logging.error(f"Error sending message for ticket {ticket_id}: {e}")
        emit('message_error', {'error': str(e)})
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@socketio.on('join_chat_room')
def on_join_chat_room(data):
    """Joins a client or operator to a specific chat room for a ticket."""
    ticket_id = data.get('ticket_id')
    if ticket_id:
        join_room(f'ticket_{ticket_id}')
        emit('status', {'msg': f'Joined ticket_{ticket_id} room'})
        logging.info(f"Client/Operator joined chat room: ticket_{ticket_id}")

@socketio.on('join_operator_branch_room')
def on_join_operator_branch_room(data):
    """Allows an operator (or admin) dashboard to listen to general branch updates."""
    branch_id = data.get('branch_id')
    if branch_id:
        room = f'operator_branch_{branch_id}'
        join_room(room)
        logging.info(f"Operator branch room joined: {room}")

@socketio.on('join_operator_personal_room')
def on_join_operator_personal_room(data):
    """Allows an individual operator to listen to their personal updates."""
    operator_id = data.get('operator_id')
    branch_id = data.get('branch_id')
    if operator_id and branch_id:
        room = f'operator_{operator_id}_{branch_id}'
        join_room(room)
        logging.info(f"Operator personal room joined: {room}")

# --- Feedback & Dispute API ---
@app.route('/api/submit_feedback', methods=['POST'])
def submit_feedback_api():
    """Submits feedback for a ticket."""
    data = request.json
    ticket_id = data.get('ticket_id')
    rating = data.get('rating')
    comment = data.get('comment')

    if not ticket_id or rating is None:
        logging.error("Attempted to submit feedback with missing ticket ID or rating.")
        return jsonify({"error": "Ticket ID and rating are required"}), 400

    conn = get_db()
    c = conn.cursor()

    ticket_info = c.execute("SELECT branch_id, operator_id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket_info:
        # conn.close()
        logging.warning(f"Attempted to submit feedback for non-existent ticket ID: {ticket_id}.")
        return jsonify({'error': 'Ticket not found'}), 404
    ticket_branch_id = ticket_info['branch_id']
    ticket_operator_id = ticket_info['operator_id']

    try:
        c.execute("INSERT INTO feedback (ticket_id, rating, comment, branch_id) VALUES (?, ?, ?, ?)",
                  (ticket_id, rating, comment, ticket_branch_id))
        conn.commit()
        socketio.emit('new_feedback', {'ticket_id': ticket_id, 'rating': rating, 'branch_id': ticket_branch_id}, room=f'admin_branch_{ticket_branch_id}')
        if ticket_operator_id:
            socketio.emit('new_feedback', {'ticket_id': ticket_id, 'rating': rating, 'branch_id': ticket_branch_id}, room=f'operator_{ticket_operator_id}_{ticket_branch_id}')
        socketio.emit('new_feedback', {'ticket_id': ticket_id, 'rating': rating, 'branch_id': ticket_branch_id}, room=f'operator_branch_{ticket_branch_id}')
        logging.info(f"New feedback submitted: Ticket ID {ticket_id}, Rating: {rating}, Branch: {ticket_branch_id}.")
        return jsonify({"message": "Feedback submitted successfully"}), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Error submitting feedback for ticket {ticket_id}: {e}")
        return jsonify({"error": "Failed to submit feedback"}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/submit_dispute', methods=['POST'])
def submit_dispute_api():
    """Submits a dispute for a ticket."""
    data = request.json
    ticket_id = data.get('ticket_id')
    comment = data.get('comment')

    if not ticket_id or not comment:
        logging.error("Attempted to submit dispute with missing ticket ID or comment.")
        return jsonify({"error": "Ticket ID and comment are required"}), 400

    conn = get_db()
    c = conn.cursor()

    ticket_info = c.execute("SELECT branch_id, operator_id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket_info:
        # conn.close()
        logging.warning(f"Attempted to submit dispute for non-existent ticket ID: {ticket_id}.")
        return jsonify({'error': 'Ticket not found'}), 404
    ticket_branch_id = ticket_info['branch_id']
    ticket_operator_id = ticket_info['operator_id']

    try:
        c.execute("INSERT INTO disputes (ticket_id, comment, branch_id) VALUES (?, ?, ?)",
                  (ticket_id, comment, ticket_branch_id))
        conn.commit()
        socketio.emit('new_dispute', {'ticket_id': ticket_id, 'branch_id': ticket_branch_id}, room=f'admin_branch_{ticket_branch_id}')
        if ticket_operator_id:
            socketio.emit('new_dispute', {'ticket_id': ticket_id, 'branch_id': ticket_branch_id}, room=f'operator_{ticket_operator_id}_{ticket_branch_id}')
        socketio.emit('new_dispute', {'ticket_id': ticket_id, 'branch_id': ticket_branch_id}, room=f'operator_branch_{ticket_branch_id}')
        logging.info(f"New dispute submitted: Ticket ID {ticket_id}, Branch: {ticket_branch_id}.")
        return jsonify({"message": "Dispute submitted successfully"}), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Error submitting dispute for ticket {ticket_id}: {e}")
        return jsonify({"error": "Failed to submit dispute"}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

# --- CRUD for translations.json ---
@app.route('/api/translations', methods=['GET'])
@login_required(role='super_admin')
def get_translations_api(current_user):
    """Returns the content of translations.json."""
    with open('translations.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    logging.info(f"Super admin {current_user['username']} fetched translations.")
    return jsonify(data)

@app.route('/api/translations', methods=['POST'])
@login_required(role='super_admin')
def update_translations_api(current_user):
    """Updates the translations.json file and reloads translations."""
    data = request.json
    try:
        with open('translations.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        load_translations() # Reload translations into memory
        logging.info(f"Super admin {current_user['username']} updated translations.")
        return jsonify({'message': 'Translations updated successfully'}), 200
    except Exception as e:
        logging.error(f"Super admin {current_user['username']} failed to update translations: {e}")
        return jsonify({'error': f'Failed to update translations: {e}'}), 500


# --- Client Ticket History ---
@app.route('/api/client_tickets/<int:user_id>', methods=['GET'])
@login_required() # Any logged-in user can view their tickets
def client_tickets(user_id, current_user):
    """Returns the ticket history for a given client user ID."""
    conn = get_db()
    # Ensure the user is requesting their own tickets if not super_admin/branch_admin
    if current_user['role'] not in ['super_admin', 'branch_admin']:
        requested_user_telegram_id = conn.execute("SELECT telegram_user_id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not requested_user_telegram_id or requested_user_telegram_id['telegram_user_id'] != session.get('telegram_user_id'): # Assuming telegram_user_id is in session for clients
            logging.warning(f"User {current_user['username']} attempted to view another user's tickets without permission.")
            return jsonify({'error': 'Unauthorized access'}), 403

    tickets = conn.execute("""
        SELECT t.id, t.number, t.status, t.start_time, t.finish_time, s.name_uz_lat as service_name
        FROM tickets t
        JOIN services s ON t.service_id = s.id
        WHERE t.client_telegram_user_id = (SELECT telegram_user_id FROM users WHERE id = ?)
        ORDER BY t.start_time DESC
        LIMIT 50
    """, (user_id,)).fetchall()
    # conn.close()
    logging.debug(f"User {current_user['username']} fetched client ticket history for user ID {user_id}.")
    return jsonify([dict(row) for row in tickets])

# --- Operator Views Client Info (VIP and History) ---
@app.route('/api/operator/client_info/<int:client_db_id>', methods=['GET'])
@login_required(role='operator')
def operator_client_info(client_db_id, current_user):
    """Returns detailed information about a client (VIP status, loyalty, ticket history) for an operator."""
    conn = get_db()
    client_user = conn.execute("SELECT id, username, is_vip, loyalty_points, telegram_user_id FROM users WHERE id = ? AND role = 'client'", (client_db_id,)).fetchone()
    if not client_user:
        # conn.close()
        logging.warning(f"Operator {current_user['username']} attempted to get info for non-existent or non-client user ID: {client_db_id}.")
        return jsonify({'error': 'Client not found or is not a client user'}), 404

    tickets = conn.execute("""
        SELECT t.id, t.number, t.status, t.start_time, t.finish_time, s.name_uz_lat as service_name
        FROM tickets t
        JOIN services s ON t.service_id = s.id
        WHERE t.client_telegram_user_id = ? AND t.branch_id = ?
        ORDER BY t.start_time DESC
        LIMIT 20
    """, (client_user['telegram_user_id'], current_user['branch_id'])).fetchall()
    # conn.close()
    logging.debug(f"Operator {current_user['username']} fetched client info for client ID {client_db_id} in branch {current_user['branch_id']}.")
    return jsonify({
        "user": dict(client_user) if client_user else None,
        "tickets": [dict(row) for row in tickets]
    })

# --- Manual Queue Management (Move, Change Status) ---
@app.route('/api/admin/move_ticket', methods=['POST'])
@login_required(role='branch_admin')
def move_ticket(current_user):
    """Allows an admin to manually reorder tickets in the queue."""
    data = request.json
    ticket_id = data.get('ticket_id')
    new_position = data.get('new_position', type=int) # 0-indexed position
    branch_id = current_user['branch_id']

    if ticket_id is None or new_position is None:
        return jsonify({'error': 'Missing ticket_id or new_position'}), 400

    conn = get_db()
    c = conn.cursor()

    # Get current queue order including VIP status
    tickets_in_queue = c.execute("""
        SELECT t.id, CASE WHEN u.is_vip = 1 THEN 0 ELSE 1 END AS vip_order, t.start_time
        FROM tickets t
        LEFT JOIN users u ON t.client_telegram_user_id = u.telegram_user_id
        WHERE t.branch_id = ? AND t.status IN ('waiting', 'redirected', 'called')
        ORDER BY vip_order ASC, t.sort_order ASC NULLS LAST, t.start_time ASC
    """, (branch_id,)).fetchall()

    current_ids = [row['id'] for row in tickets_in_queue]

    if ticket_id not in current_ids:
        # conn.close()
        logging.warning(f"Admin {current_user['username']} attempted to move non-existent or inactive ticket {ticket_id}.")
        return jsonify({'error': 'Invalid ticket or ticket not in active queue'}), 400

    if not (0 <= new_position < len(current_ids)):
        # conn.close()
        logging.warning(f"Admin {current_user['username']} attempted to move ticket {ticket_id} to invalid position {new_position}.")
        return jsonify({'error': 'Invalid new position'}), 400

    # Remove the ticket from its current position and insert into new position
    current_ids.remove(ticket_id)
    current_ids.insert(new_position, ticket_id)

    try:
        # Update sort_order for all affected tickets
        for idx, tid in enumerate(current_ids):
            c.execute("UPDATE tickets SET sort_order = ? WHERE id = ?", (idx, tid))
        conn.commit()

        # Notify clients about queue change (can be done more granularly, but this is a broad update)
        socketio.emit('queue_updated', {'branch_id': branch_id}, room=f'display_{branch_id}')
        socketio.emit('queue_updated', {'branch_id': branch_id}, room=f'operator_branch_{branch_id}')

        logging.info(f"Admin {current_user['username']} reordered queue in branch {branch_id}: ticket {ticket_id} moved to position {new_position}.")
        return jsonify({'message': 'Queue reordered successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Admin {current_user['username']} failed to move ticket {ticket_id}: {e}")
        return jsonify({'error': 'Failed to reorder queue'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/admin/set_ticket_status', methods=['POST'])
@login_required(role='branch_admin')
def set_ticket_status(current_user):
    """Allows an admin to manually set the status of a ticket."""
    data = request.json
    ticket_id = data.get('ticket_id')
    status = data.get('status')
    branch_id = current_user['branch_id']

    allowed = ['waiting', 'called', 'finished', 'redirected', 'skipped', 'no_show', 'cancelled']
    if status not in allowed:
        return jsonify({'error': 'Invalid status'}), 400
    if not ticket_id:
        return jsonify({'error': 'Missing ticket_id'}), 400

    conn = get_db()
    c = conn.cursor()

    # Verify ticket belongs to the admin's branch
    ticket_check = c.execute("SELECT id FROM tickets WHERE id = ? AND branch_id = ?", (ticket_id, branch_id)).fetchone()
    if not ticket_check:
        # conn.close()
        logging.warning(f"Admin {current_user['username']} attempted to set status for ticket {ticket_id} not in their branch.")
        return jsonify({'error': 'Ticket not found in your branch'}), 404

    try:
        c.execute("UPDATE tickets SET status = ?, call_time = CASE WHEN ? = 'called' THEN CURRENT_TIMESTAMP ELSE call_time END, finish_time = CASE WHEN ? IN ('finished', 'cancelled', 'no_show') THEN CURRENT_TIMESTAMP ELSE finish_time END WHERE id = ?",
                  (status, status, status, ticket_id))
        conn.commit()

        # Emit update to all relevant dashboards
        socketio.emit('ticket_status_updated', {'ticket_id': ticket_id, 'status': status, 'branch_id': branch_id}, room=f'display_{branch_id}')
        socketio.emit('ticket_status_updated', {'ticket_id': ticket_id, 'status': status, 'branch_id': branch_id}, room=f'operator_branch_{branch_id}')
        socketio.emit('ticket_status_updated', {'ticket_id': ticket_id, 'status': status, 'branch_id': branch_id}, room=f'admin_branch_{branch_id}')

        logging.info(f"Admin {current_user['username']} set status of ticket {ticket_id} to {status}.")
        return jsonify({'message': 'Status updated successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Admin {current_user['username']} failed to set status for ticket {ticket_id}: {e}")
        return jsonify({'error': 'Failed to update status'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

# --- VIP and Loyalty Management ---
@app.route('/api/admin/set_vip', methods=['POST'])
@login_required(role='branch_admin') # Only branch_admin can set VIP for their branch users
def set_vip(current_user):
    """Allows an admin to set a client's VIP status."""
    data = request.json
    user_id = data.get('user_id')
    is_vip = bool(data.get('is_vip'))

    if user_id is None or is_vip is None:
        return jsonify({'error': 'Missing user_id or is_vip status'}), 400

    conn = get_db()
    c = conn.cursor()

    # Ensure the user is a client and belongs to the admin's branch (unless super_admin)
    user_to_update = conn.execute("SELECT id, role, branch_id FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_to_update or user_to_update['role'] != 'client':
        # conn.close()
        logging.warning(f"Admin {current_user['username']} attempted to set VIP for non-existent or non-client user {user_id}.")
        return jsonify({'error': 'User not found or is not a client'}), 404
    if current_user['role'] == 'branch_admin' and user_to_update['branch_id'] != current_user['branch_id']:
        # conn.close()
        logging.warning(f"Branch admin {current_user['username']} attempted to set VIP for user {user_id} outside their branch.")
        return jsonify({'error': 'Unauthorized: User not in your branch'}), 403

    try:
        c.execute("UPDATE users SET is_vip = ? WHERE id = ?", (int(is_vip), user_id))
        conn.commit()
        logging.info(f"Admin {current_user['username']} set VIP status for user {user_id} to {is_vip}.")
        return jsonify({'message': 'VIP status updated successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Admin {current_user['username']} failed to set VIP status for user {user_id}: {e}")
        return jsonify({'error': 'Failed to update VIP status'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/admin/add_loyalty', methods=['POST'])
@login_required(role='branch_admin') # Only branch_admin can add loyalty for their branch users
def add_loyalty(current_user):
    """Allows an admin to manually add loyalty points to a client."""
    data = request.json
    user_id = data.get('user_id')
    points = int(data.get('points', 1)) # Default to 1 point

    if user_id is None:
        return jsonify({'error': 'Missing user_id'}), 400
    if points <= 0:
        return jsonify({'error': 'Points must be positive'}), 400

    conn = get_db()
    c = conn.cursor()

    # Ensure the user is a client and belongs to the admin's branch (unless super_admin)
    user_to_update = conn.execute("SELECT id, role, branch_id FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_to_update or user_to_update['role'] != 'client':
        # conn.close()
        logging.warning(f"Admin {current_user['username']} attempted to add loyalty for non-existent or non-client user {user_id}.")
        return jsonify({'error': 'User not found or is not a client'}), 404
    if current_user['role'] == 'branch_admin' and user_to_update['branch_id'] != current_user['branch_id']:
        # conn.close()
        logging.warning(f"Branch admin {current_user['username']} attempted to add loyalty for user {user_id} outside their branch.")
        return jsonify({'error': 'Unauthorized: User not in your branch'}), 403

    try:
        c.execute("UPDATE users SET loyalty_points = loyalty_points + ? WHERE id = ?", (points, user_id))
        conn.commit()
        logging.info(f"Admin {current_user['username']} added {points} loyalty points to user {user_id}.")
        return jsonify({'message': 'Loyalty points added successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Admin {current_user['username']} failed to add loyalty points to user {user_id}: {e}")
        return jsonify({'error': 'Failed to add loyalty points'}), 500
    # finally: # Managed by teardown_appcontext
    #     conn.close()

@app.route('/api/operator/set_availability', methods=['POST'])
@login_required(role='operator')
def set_operator_availability(current_user):
    """Allows an operator to set their availability status and time slot."""
    operator_id = current_user['id']
    data = request.json
    is_available = data.get('is_available')
    start_time_str = data.get('start_time')
    end_time_str = data.get('end_time')

    conn = get_db()
    c = conn.cursor()

    update_fields = []
    update_values = []

    if is_available is not None:
        update_fields.append("is_available = ?")
        update_values.append(bool(is_available))
    if start_time_str is not None:
        update_fields.append("available_start_time = ?")
        update_values.append(start_time_str)
    if end_time_str is not None:
        update_fields.append("available_end_time = ?")
        update_values.append(end_time_str)

    if not update_fields:
        return jsonify({'message': 'No fields to update'}), 200

    update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
    update_values.append(operator_id)

    try:
        c.execute(update_query, tuple(update_values))
        conn.commit()
        logging.info(f"Operator {current_user['username']} updated availability: is_available={is_available}, start={start_time_str}, end={end_time_str}.")
        return jsonify({'message': 'Availability updated successfully'}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Operator {current_user['username']} failed to update availability: {e}")
        return jsonify({'error': 'Failed to update availability'}), 500


# --- Telegram Bot Setup and Handlers ---

# Helper to get branch_id from telegram_user_id (maps Telegram user to our internal branch_id)
def get_user_branch_id(telegram_user_id: int):
    """Retrieves branch_id for a given Telegram user. If not found, attempts to assign to the first branch."""
    conn = get_db() # Use get_db for consistency with Flask app context
    user_branch = conn.execute("SELECT branch_id FROM users WHERE telegram_user_id = ?", (telegram_user_id,)).fetchone()

    if user_branch:
        return user_branch['branch_id']
    else:
        # If user is not found, but a branch exists, register them as a client to this branch.
        first_branch = conn.execute("SELECT id FROM branches LIMIT 1").fetchone()
        if first_branch:
            try:
                c = conn.cursor()
                c.execute("INSERT INTO users (username, role, telegram_user_id, branch_id) VALUES (?, ?, ?, ?)",
                          (f"TelegramUser_{telegram_user_id}", 'client', telegram_user_id, first_branch['id']))
                conn.commit()
                logging.info(f"Telegram user {telegram_user_id} registered as client and assigned to branch ID: {first_branch['id']}.")
                return first_branch['id']
            except sqlite3.IntegrityError:
                # This can happen if user was just inserted by another concurrent call
                logging.warning(f"Telegram user {telegram_user_id} already exists (race condition during initial registration). Re-fetching branch_id.")
                user_branch_after_retry = conn.execute("SELECT branch_id FROM users WHERE telegram_user_id = ?", (telegram_user_id,)).fetchone()
                return user_branch_after_retry['branch_id'] if user_branch_after_retry else None
            except Exception as e:
                logging.error(f"Error assigning Telegram user {telegram_user_id} to first branch: {e}")
                return None
        else:
            logging.error(f"Telegram user {telegram_user_id} not found and no branches exist in DB. Cannot assign branch_id.")
            return None

# Helper to get branch name for messages
def get_branch_name_for_bot(branch_id: int):
    """Retrieves branch name for use in bot messages."""
    conn = get_db()
    branch_name_row = conn.execute("SELECT name FROM branches WHERE id = ?", (branch_id,)).fetchone()
    return branch_name_row['name'] if branch_name_row else "Неизвестный филиал"

# Define FSM states for various bot interactions
class ClientForm(StatesGroup):
    """FSM states for client interactions via Telegram bot."""
    SelectingCategory = State()
    SelectingService = State()
    RedirectingTicket = State()

class OperatorForm(StatesGroup):
    """FSM states for operator interactions via Telegram bot (if any complex flows)."""
    pass

# Function to register all common Aiogram handlers for a given dispatcher
def register_aiogram_handlers(dp: Dispatcher):
    """Registers all Aiogram message and callback query handlers."""
    router = Router()
    dp.include_router(router)

    # Middleware to inject branch_id into every update for easy access in handlers
    @router.message.middleware()
    @router.callback_query.middleware()
    async def branch_id_middleware(handler, event, data):
        telegram_user_id = event.from_user.id
        # Use Flask app context for DB operations in a separate thread
        with app.app_context():
            branch_id = get_user_branch_id(telegram_user_id)

        if branch_id is None:
            logging.error(f"Could not find or assign branch_id for Telegram user {telegram_user_id}. Update ignored.")
            error_message = get_text('uz_lat', 'error_during_registration')
            if isinstance(event, types.Message):
                await event.answer(error_message)
            elif isinstance(event, types.CallbackQuery):
                await event.answer(error_message)
            return

        data['branch_id'] = branch_id
        return await handler(event, data)

    # --- Client Commands ---
    @router.message(Command('start'))
    async def cmd_start(message: types.Message, state: FSMContext, branch_id: int):
        """Handles the /start command for clients."""
        # This part ensures the user is registered in our DB or fetches their branch_id
        with app.app_context():
            conn = get_db()
            user_row = conn.execute("SELECT id, username FROM users WHERE telegram_user_id = ? AND branch_id = ?", (message.from_user.id, branch_id)).fetchone()

            if not user_row:
                try:
                    conn.execute("INSERT INTO users (username, role, telegram_user_id, branch_id) VALUES (?, ?, ?, ?)",
                                 (message.from_user.full_name or f"TelegramUser_{message.from_user.id}", 'client', message.from_user.id, branch_id))
                    conn.commit()
                    logging.info(f"New client {message.from_user.id} registered for branch {branch_id} via /start command.")
                except sqlite3.IntegrityError:
                    logging.warning(f"Client {message.from_user.id} already exists for branch {branch_id} (possible race condition or user already registered).")
                except Exception as e:
                    logging.error(f"Error registering new client {message.from_user.id} for branch {branch_id} via /start: {e}")
                    await message.answer(get_text('uz_lat', 'error_during_registration'))
                    return # Exit early if registration failed

            # Get branch name for welcome message
            branch_name = get_branch_name_for_bot(branch_id)

        keyboard = types.ReplyKeyboardMarkup(
            keyboard=[
                [types.KeyboardButton(text=get_text('uz_lat', 'take_ticket_btn'))],
                [types.KeyboardButton(text=get_text('uz_lat', 'my_current_ticket_btn'))],
                [types.KeyboardButton(text=get_text('uz_lat', 'queue_status_btn'))],
                [types.KeyboardButton(text=get_text('uz_lat', 'chat_with_operator_btn'))],
                [types.KeyboardButton(text=get_text('uz_lat', 'my_ticket_history_btn'))], # Добавлена кнопка
                [types.KeyboardButton(text="/faq")] # Добавлена кнопка
            ],
            resize_keyboard=True
        )
        await message.answer(get_text('uz_lat', 'welcome_message', branch_name=branch_name), reply_markup=keyboard)

    @router.message(F.text == get_text('uz_lat', 'take_ticket_btn'))
    async def select_category_for_ticket(message: types.Message, state: FSMContext, branch_id: int):
        """Allows clients to select a service category to take a ticket."""
        with app.app_context():
            conn = get_db()
            categories = conn.execute("SELECT id, name_uz_lat FROM categories WHERE branch_id = ? AND parent_id IS NULL AND has_operators = 1", (branch_id,)).fetchall()

        if not categories:
            await message.answer(get_text('uz_lat', 'no_services_available'))
            return

        keyboard_buttons = [[types.InlineKeyboardButton(text=cat['name_uz_lat'], callback_data=f"select_category_{cat['id']}")] for cat in categories]
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)
        await state.set_state(ClientForm.SelectingCategory)
        await message.answer(get_text('uz_lat', 'select_service_category'), reply_markup=keyboard)

    @router.callback_query(ClientForm.SelectingCategory, F.data.startswith('select_category_'))
    async def select_service_from_category(callback_query: types.CallbackQuery, state: FSMContext, branch_id: int):
        """Allows clients to select a service within a chosen category."""
        category_id = int(callback_query.data.split('_')[2])
        await state.update_data(selected_category_id=category_id)

        with app.app_context():
            conn = get_db()
            services = conn.execute("SELECT id, name_uz_lat FROM services WHERE category_id = ? AND is_active = 1 AND branch_id = ?", (category_id, branch_id)).fetchall()

            category_name_row = conn.execute("SELECT name_uz_lat FROM categories WHERE id = ? AND branch_id = ?", (category_id, branch_id)).fetchone()

        category_name = category_name_row['name_uz_lat'] if category_name_row else get_text('uz_lat', 'category_default_name')

        if not services:
            await callback_query.message.edit_text(get_text('uz_lat', 'no_services_in_category'))
            await state.clear()
            return

        keyboard_buttons = [[types.InlineKeyboardButton(text=svc['name_uz_lat'], callback_data=f"take_ticket_svc_{svc['id']}")] for svc in services]
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)

        await callback_query.message.edit_text(get_text('uz_lat', 'services_in_category', category_name=category_name), reply_markup=keyboard)
        await state.set_state(ClientForm.SelectingService)
        await callback_query.answer()

    @router.callback_query(ClientForm.SelectingService, F.data.startswith('take_ticket_svc_'))
    async def issue_ticket_callback(callback_query: types.CallbackQuery, state: FSMContext, branch_id: int):
        """Issues a ticket for the selected service."""
        service_id = int(callback_query.data.split('_')[3])
        client_telegram_user_id = callback_query.from_user.id

        with app.app_context():
            conn = get_db()
            service = conn.execute("SELECT name_uz_lat FROM services WHERE id = ? AND branch_id = ? AND is_active = 1", (service_id, branch_id)).fetchone()
            if not service:
                await callback_query.message.edit_text(get_text('uz_lat', 'service_not_found'))
                await state.clear()
                return

            try:
                today_str = datetime.now().strftime("%Y-%m-%d")
                c = conn.cursor()
                c.execute("""
                    SELECT COUNT(*) FROM tickets
                    WHERE branch_id = ? AND DATE(start_time) = DATE(?)
                """, (branch_id, today_str))
                ticket_count_today = c.fetchone()[0]

                ticket_number = f"BR{branch_id}-{ticket_count_today + 1:03d}"
                ticket_uuid = str(uuid.uuid4())

                c.execute("""
                    INSERT INTO tickets (id, number, service_id, client_telegram_user_id, status, branch_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (ticket_uuid, ticket_number, service_id, client_telegram_user_id, 'waiting', branch_id))

                # Update the user's current_ticket_id and add loyalty points
                c.execute("UPDATE users SET current_ticket_id = ?, loyalty_points = loyalty_points + 1 WHERE telegram_user_id = ?",
                          (ticket_uuid, client_telegram_user_id))
                conn.commit()

                await callback_query.message.edit_text(
                    get_text('uz_lat', 'ticket_issued_message',
                        ticket_number=ticket_number,
                        service_name=service['name_uz_lat'],
                        status=get_text('uz_lat', 'status_waiting')
                    ),
                    parse_mode="Markdown"
                )

                ticket_info_for_socket = {
                    'id': ticket_uuid,
                    'number': ticket_number,
                    'service_name': service['name_uz_lat'],
                    'status': 'waiting',
                    'branch_id': branch_id
                }
                socketio.emit('new_ticket', ticket_info_for_socket, room=f'display_{branch_id}')
                socketio.emit('new_ticket', ticket_info_for_socket, room=f'operator_branch_{branch_id}')
                logging.info(f"Telegram bot issued ticket: {ticket_number} (Branch: {branch_id}).")

            except Exception as e:
                conn.rollback()
                logging.error(f"Error issuing ticket via bot for branch {branch_id}: {e}")
                await callback_query.message.edit_text(get_text('uz_lat', 'failed_to_issue_ticket'))
            finally:
                await state.clear()
            await callback_query.answer()

    @router.message(F.text == get_text('uz_lat', 'my_current_ticket_btn'))
    async def get_my_ticket_status(message: types.Message, branch_id: int):
        """Allows clients to check the status of their latest ticket."""
        with app.app_context():
            conn = get_db()
            ticket_info = conn.execute("""
                SELECT t.id, t.number, s.name_uz_lat as service_name, t.status, t.call_time, t.finish_time,
                       u_op.username as operator_username, u_client.is_vip, u_client.loyalty_points
                FROM tickets t
                JOIN services s ON t.service_id = s.id
                LEFT JOIN users u_op ON t.operator_id = u_op.id
                LEFT JOIN users u_client ON t.client_telegram_user_id = u_client.telegram_user_id
                WHERE t.client_telegram_user_id = ? AND t.branch_id = ?
                ORDER BY t.start_time DESC
                LIMIT 1
            """, (message.from_user.id, branch_id)).fetchone()

        if not ticket_info:
            await message.answer(get_text('uz_lat', 'no_active_ticket'))
            return

        status_text = get_text('uz_lat', 'your_ticket_info',
            ticket_number=ticket_info['number'],
            service_name=ticket_info['service_name'],
            status=get_text('uz_lat', f"status_{ticket_info['status']}")
        )
        if ticket_info['is_vip']:
            status_text += "\n" + get_text('uz_lat', 'vip_status')
        if ticket_info['loyalty_points'] is not None:
            status_text += "\n" + get_text('uz_lat', 'loyalty_points_info', points=ticket_info['loyalty_points'])

        if ticket_info['status'] == 'called' and ticket_info['operator_username']:
            status_text += get_text('uz_lat', 'operator_info', operator_username=ticket_info['operator_username'])
        if ticket_info['status'] == 'finished' and ticket_info['finish_time']:
            status_text += get_text('uz_lat', 'finished_at_info', finish_time=ticket_info['finish_time'])

        inline_keyboard_buttons = []
        base_url = FLASK_EXTERNAL_URL if FLASK_EXTERNAL_URL else f"http://{FLASK_RUN_HOST}:{FLASK_RUN_PORT}"

        chat_url = f"{base_url}/chat/{ticket_info['id']}"
        inline_keyboard_buttons.append([types.InlineKeyboardButton(text=get_text('uz_lat', 'chat_with_operator_btn'), url=chat_url)])

        if ticket_info['status'] == 'finished':
            feedback_url = f"{base_url}/feedback/{ticket_info['id']}"
            dispute_url = f"{base_url}/dispute/{ticket_info['id']}"
            inline_keyboard_buttons.extend([
                [types.InlineKeyboardButton(text=get_text('uz_lat', 'give_feedback_btn'), url=feedback_url)],
                [types.InlineKeyboardButton(text=get_text('uz_lat', 'file_dispute_btn'), url=dispute_url)],
            ])

        inline_keyboard = types.InlineKeyboardMarkup(inline_keyboard=inline_keyboard_buttons) if inline_keyboard_buttons else None
        await message.answer(status_text, parse_mode="Markdown", reply_markup=inline_keyboard)

    @router.message(F.text == get_text('uz_lat', 'queue_status_btn'))
    async def get_queue_status(message: types.Message, branch_id: int):
        """Allows clients to view the current queue status for their branch."""
        with app.app_context():
            conn = get_db()
            queue_tickets = conn.execute("""
                SELECT t.number, s.name_uz_lat as service_name, t.status,
                       CASE WHEN u.is_vip = 1 THEN 0 ELSE 1 END AS vip_order
                FROM tickets t
                JOIN services s ON t.service_id = s.id
                LEFT JOIN users u ON t.client_telegram_user_id = u.telegram_user_id
                WHERE t.branch_id = ? AND t.status IN ('waiting', 'called')
                ORDER BY vip_order ASC, t.sort_order ASC NULLS LAST, t.start_time ASC
                LIMIT 5
            """, (branch_id,)).fetchall()

        if not queue_tickets:
            await message.answer(get_text('uz_lat', 'queue_empty'))
            return

        response_text = get_text('uz_lat', 'current_queue_title') + "\n"
        for ticket in queue_tickets:
            response_text += get_text('uz_lat', 'queue_item',
                number=ticket['number'],
                service_name=ticket['service_name'],
                status=get_text('uz_lat', f"status_{ticket['status']}")
            ) + "\n"
        await message.answer(response_text, parse_mode="Markdown")

    @router.message(F.text == get_text('uz_lat', 'chat_with_operator_btn'))
    async def provide_chat_link(message: types.Message, branch_id: int):
        """Provides a link to the web-based chat for the client's current/last ticket."""
        base_url = FLASK_EXTERNAL_URL if FLASK_EXTERNAL_URL else f"http://{FLASK_RUN_HOST}:{FLASK_RUN_PORT}"

        with app.app_context():
            conn = get_db()
            user_ticket_info = conn.execute("SELECT current_ticket_id FROM users WHERE telegram_user_id = ?",
                                  (message.from_user.id,)).fetchone()

            ticket_id = user_ticket_info['current_ticket_id'] if user_ticket_info else None

            if not ticket_id:
                await message.answer(get_text('uz_lat', 'no_active_ticket_for_chat'))
                return

            ticket_status_check = conn.execute("SELECT status FROM tickets WHERE id = ? AND branch_id = ?",
                                               (ticket_id, branch_id)).fetchone()
            if not ticket_status_check or ticket_status_check['status'] in ['cancelled', 'no_show', 'finished']:
                await message.answer(get_text('uz_lat', 'ticket_not_eligible_for_chat'))
                return

        chat_url = f"{base_url}/chat/{ticket_id}"
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=[
            [types.InlineKeyboardButton(text=get_text('uz_lat', 'open_chat_btn'), url=chat_url)]
        ])
        await message.answer(get_text('uz_lat', 'open_chat_prompt'), reply_markup=keyboard)

    @router.message(F.text == get_text('uz_lat', 'my_ticket_history_btn'))
    async def get_client_ticket_history(message: types.Message, branch_id: int):
        """Displays the client's past ticket history."""
        with app.app_context():
            conn = get_db()
            tickets = conn.execute("""
                SELECT t.id, t.number, t.status, t.start_time, t.finish_time, s.name_uz_lat as service_name
                FROM tickets t
                JOIN services s ON t.service_id = s.id
                WHERE t.client_telegram_user_id = ? AND t.branch_id = ?
                ORDER BY t.start_time DESC
                LIMIT 10
            """, (message.from_user.id, branch_id)).fetchall()

        if not tickets:
            await message.answer(get_text('uz_lat', 'no_past_tickets'))
            return

        response_text = get_text('uz_lat', 'your_ticket_history_title') + "\n"
        for ticket in tickets:
            response_text += get_text('uz_lat', 'ticket_history_item',
                number=ticket['number'],
                service_name=ticket['service_name'],
                status=get_text('uz_lat', f"status_{ticket['status']}"),
                start_time=ticket['start_time'][:16] # Show YYYY-MM-DD HH:MM
            ) + "\n"
        await message.answer(response_text, parse_mode="Markdown")

    @router.message(Command('faq'))
    async def cmd_faq(message: types.Message, branch_id: int):
        """Provides answers to frequently asked questions."""
        # This can be expanded to fetch from a DB or config for more complex FAQs
        faq_text = get_text('uz_lat', 'faq_title') + "\n\n" + \
                   get_text('uz_lat', 'faq_q1') + "\n" + \
                   get_text('uz_lat', 'faq_a1') + "\n\n" + \
                   get_text('uz_lat', 'faq_q2') + "\n" + \
                   get_text('uz_lat', 'faq_a2')
        await message.answer(faq_text, parse_mode="Markdown")

    # --- Operator Commands (restricted by role in database) ---
    @router.message(Command('operator'))
    async def cmd_operator_panel(message: types.Message, branch_id: int):
        """Provides operator panel options if user is authorized."""
        with app.app_context():
            conn = get_db()
            user_role_info = conn.execute("SELECT role FROM users WHERE telegram_user_id = ?", (message.from_user.id,)).fetchone()

        if not user_role_info or user_role_info['role'] not in ['operator', 'branch_admin', 'super_admin']:
            await message.answer(get_text('uz_lat', 'unauthorized_operator_access'))
            return

        keyboard = types.ReplyKeyboardMarkup(
            keyboard=[
                [types.KeyboardButton(text="/call_next_ticket")],
                [types.KeyboardButton(text="/my_queue")],
                [types.KeyboardButton(text="/stats")],
                [types.KeyboardButton(text="/set_availability")], # Добавлена кнопка
            ],
            resize_keyboard=True
        )
        await message.answer(get_text('uz_lat', 'operator_panel_title'), reply_markup=keyboard)

    @router.message(Command('call_next_ticket'))
    async def cmd_call_next_ticket(message: types.Message, branch_id: int):
        """Allows an authorized operator to call the next ticket in their branch."""
        with app.app_context():
            conn = get_db()
            operator_info = conn.execute("SELECT id, role, is_available, available_start_time, available_end_time FROM users WHERE telegram_user_id = ?", (message.from_user.id,)).fetchone()

            if not operator_info or operator_info['role'] not in ['operator', 'branch_admin', 'super_admin']:
                await message.answer(get_text('uz_lat', 'unauthorized_to_call_tickets'))
                return

            if not operator_info['is_available']:
                await message.answer(get_text('uz_lat', 'not_available_to_call'))
                return

            current_time = datetime.now()
            if operator_info['available_start_time'] and current_time < datetime.fromisoformat(operator_info['available_start_time']):
                await message.answer(get_text('uz_lat', 'not_yet_available'))
                return
            if operator_info['available_end_time'] and current_time > datetime.fromisoformat(operator_info['available_end_time']):
                await message.answer(get_text('uz_lat', 'availability_ended'))
                return

            operator_id = operator_info['id']

            ticket_to_call = conn.execute("""
                SELECT t.id, t.number, s.name_uz_lat as service_name, t.client_telegram_user_id
                FROM tickets t
                JOIN services s ON t.service_id = s.id
                LEFT JOIN users op_assigned ON s.operator_id = op_assigned.id
                LEFT JOIN users client_user ON t.client_telegram_user_id = client_user.telegram_user_id
                WHERE t.branch_id = ?
                      AND t.status IN ('waiting', 'redirected')
                      AND (op_assigned.id = ? OR op_assigned.id IS NULL) -- Assigned to this operator or unassigned
                ORDER BY CASE WHEN client_user.is_vip = 1 THEN 0 ELSE 1 END ASC,
                         t.sort_order ASC NULLS LAST, t.start_time ASC
                LIMIT 1
            """, (branch_id, operator_id)).fetchone()

            if not ticket_to_call:
                await message.answer(get_text('uz_lat', 'no_waiting_tickets_for_you'))
                return

            try:
                conn.execute("UPDATE tickets SET status = 'called', operator_id = ?, call_time = CURRENT_TIMESTAMP WHERE id = ?",
                             (operator_id, ticket_to_call['id']))
                conn.commit()

                updated_ticket = conn.execute("""
                    SELECT t.id, t.number, t.status, t.call_time, u.username as operator_username,
                           s.name_uz_lat as service_name_uz_lat, t.client_telegram_user_id
                    FROM tickets t
                    JOIN services s ON t.service_id = s.id
                    LEFT JOIN users u ON t.operator_id = u.id
                    WHERE t.id = ?
                """, (ticket_to_call['id'],)).fetchone()

                ticket_data_to_emit = {
                    'id': updated_ticket['id'],
                    'number': updated_ticket['number'],
                    'service_name': updated_ticket['service_name_uz_lat'],
                    'status': updated_ticket['status'],
                    'operator_username': updated_ticket['operator_username'],
                    'branch_id': branch_id
                }

                socketio.emit('ticket_called', ticket_data_to_emit, room=f'display_{branch_id}')
                socketio.emit('ticket_called', ticket_data_to_emit, room=f'operator_{operator_id}_{branch_id}')
                socketio.emit('ticket_called', ticket_data_to_emit, room=f'operator_branch_{branch_id}')
                logging.info(f"Telegram bot called ticket: {updated_ticket['number']} (Operator ID: {operator_id}, Branch: {branch_id}).")

                if bot and updated_ticket['client_telegram_user_id']:
                    client_tg_id = updated_ticket['client_telegram_user_id']
                    # Get the client's preferred language from the 'users' table
                    client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
                    client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

                    message_text = get_text(client_lang, 'your_ticket_info',
                                            ticket_number=updated_ticket['number'],
                                            service_name=updated_ticket['service_name_uz_lat'],
                                            status=get_text(client_lang, 'status_called'))
                    message_text += get_text(client_lang, 'operator_info', operator_username=updated_ticket['operator_username'])

                    try:
                        asyncio.run_coroutine_threadsafe(
                            bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                            dp.loop
                        )
                        logging.info(f"Telegram notification sent to client {client_tg_id} for ticket {updated_ticket['number']}.")
                    except Exception as e:
                        logging.error(f"Failed to send Telegram notification to client {client_tg_id}: {e}")

                base_url = FLASK_EXTERNAL_URL if FLASK_EXTERNAL_URL else f"http://{FLASK_RUN_HOST}:{FLASK_RUN_PORT}"

                keyboard = types.InlineKeyboardMarkup(inline_keyboard=[
                    [types.InlineKeyboardButton(text=get_text('uz_lat', 'finish_ticket_btn'), callback_data=f"finish_ticket_{ticket_to_call['id']}")],
                    [types.InlineKeyboardButton(text=get_text('uz_lat', 'redirect_ticket_btn'), callback_data=f"redirect_ticket_prompt_{ticket_to_call['id']}")],
                    [types.InlineKeyboardButton(text=get_text('uz_lat', 'cancel_ticket_btn'), callback_data=f"cancel_ticket_{ticket_to_call['id']}")],
                    [types.InlineKeyboardButton(text=get_text('uz_lat', 'no_show_ticket_btn'), callback_data=f"no_show_ticket_{ticket_to_call['id']}")],
                    [types.InlineKeyboardButton(text=get_text('uz_lat', 'skip_ticket_btn'), callback_data=f"skip_ticket_{ticket_to_call['id']}")],
                    [types.InlineKeyboardButton(text=get_text('uz_lat', 'chat_with_client_btn'), url=f"{base_url}/chat/{ticket_to_call['id']}")]
                ])
                await message.answer(get_text('uz_lat', 'actions_for_current_ticket'), reply_markup=keyboard)
            except Exception as e:
                conn.rollback()
                logging.error(f"Operator {operator_info['username']} failed to process call_next_ticket command for branch {branch_id}: {e}")
                await message.answer(get_text('uz_lat', 'failed_to_issue_ticket'))


    @router.callback_query(F.data.startswith('finish_ticket_'))
    async def cb_finish_ticket(callback_query: types.CallbackQuery, branch_id: int):
        """Callback to finish a ticket."""
        ticket_id = callback_query.data.split('_')[2]
        with app.app_context():
            conn = get_db()
            operator_info = conn.execute("SELECT id FROM users WHERE telegram_user_id = ?", (callback_query.from_user.id,)).fetchone()

            if not operator_info:
                await callback_query.answer(get_text('uz_lat', 'unauthorized_action'))
                return

            c = conn.cursor()
            ticket_check = c.execute("SELECT id, client_telegram_user_id FROM tickets WHERE id = ? AND operator_id = ? AND branch_id = ? AND status = 'called'",
                                     (ticket_id, operator_info['id'], branch_id)).fetchone()
            if not ticket_check:
                await callback_query.answer(get_text('uz_lat', 'ticket_not_callable'))
                return

            client_tg_id = ticket_check['client_telegram_user_id']

            try:
                c.execute("UPDATE tickets SET status = 'finished', finish_time = CURRENT_TIMESTAMP WHERE id = ?", (ticket_id,))
                if client_tg_id:
                    c.execute("UPDATE users SET current_ticket_id = NULL WHERE telegram_user_id = ? AND current_ticket_id = ?",
                              (client_tg_id, ticket_id))
                conn.commit()

                socketio.emit('ticket_finished', {'ticket_id': ticket_id, 'status': 'finished', 'branch_id': branch_id}, room=f'display_{branch_id}')
                socketio.emit('ticket_finished', {'ticket_id': ticket_id, 'status': 'finished', 'branch_id': branch_id}, room=f'operator_{operator_info["id"]}_{branch_id}')
                socketio.emit('ticket_finished', {'ticket_id': ticket_id, 'status': 'finished', 'branch_id': branch_id}, room=f'operator_branch_{branch_id}')
                await callback_query.message.edit_text(get_text('uz_lat', 'ticket_finished_msg', ticket_id=ticket_id), parse_mode="Markdown")
                await callback_query.answer()

                base_url = FLASK_EXTERNAL_URL if FLASK_EXTERNAL_URL else f"http://{FLASK_RUN_HOST}:{FLASK_RUN_PORT}"
                if bot and client_tg_id:
                    # Get the client's preferred language from the 'users' table
                    client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
                    client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

                    feedback_url = f"{base_url}/feedback/{ticket_id}"
                    dispute_url = f"{base_url}/dispute/{ticket_id}"
                    message_text = get_text(client_lang, 'ticket_finished_msg', ticket_id=ticket_id) + "\n" + \
                                   get_text(client_lang, 'give_feedback_btn') + f": {feedback_url}\n" + \
                                   get_text(client_lang, 'file_dispute_btn') + f": {dispute_url}"
                    asyncio.run_coroutine_threadsafe(
                        bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                        dp.loop
                    )
                    logging.info(f"Telegram feedback/dispute prompt sent to client {client_tg_id} for ticket {ticket_id}.")
            except Exception as e:
                conn.rollback()
                logging.error(f"Operator {operator_info['username']} failed to finish ticket {ticket_id}: {e}")
                await callback_query.answer(f"Error finishing ticket: {e}")


    @router.callback_query(F.data.startswith('cancel_ticket_'))
    async def cb_cancel_ticket(callback_query: types.CallbackQuery, branch_id: int):
        """Callback to cancel a ticket."""
        ticket_id = callback_query.data.split('_')[2]
        with app.app_context():
            conn = get_db()
            operator_info = conn.execute("SELECT id FROM users WHERE telegram_user_id = ?", (callback_query.from_user.id,)).fetchone()

            if not operator_info:
                await callback_query.answer(get_text('uz_lat', 'unauthorized_action'))
                return

            c = conn.cursor()
            ticket_check = c.execute("SELECT id, client_telegram_user_id FROM tickets WHERE id = ? AND operator_id = ? AND branch_id = ? AND status = 'called'",
                                     (ticket_id, operator_info['id'], branch_id)).fetchone()
            if not ticket_check:
                await callback_query.answer(get_text('uz_lat', 'ticket_not_callable'))
                return

            client_tg_id = ticket_check['client_telegram_user_id']

            try:
                c.execute("UPDATE tickets SET status = 'cancelled', finish_time = CURRENT_TIMESTAMP WHERE id = ?", (ticket_id,))
                if client_tg_id:
                    c.execute("UPDATE users SET current_ticket_id = NULL WHERE telegram_user_id = ? AND current_ticket_id = ?",
                              (client_tg_id, ticket_id))
                conn.commit()
                socketio.emit('ticket_cancelled', {'ticket_id': ticket_id, 'status': 'cancelled', 'branch_id': branch_id}, room=f'display_{branch_id}')
                socketio.emit('ticket_cancelled', {'ticket_id': ticket_id, 'status': 'cancelled', 'branch_id': branch_id}, room=f'operator_{operator_info["id"]}_{branch_id}')
                socketio.emit('ticket_cancelled', {'ticket_id': ticket_id, 'status': 'cancelled', 'branch_id': branch_id}, room=f'operator_branch_{branch_id}')
                await callback_query.message.edit_text(get_text('uz_lat', 'ticket_cancelled_msg', ticket_id=ticket_id), parse_mode="Markdown")
                await callback_query.answer()

                if bot and client_tg_id:
                    # Get the client's preferred language from the 'users' table
                    client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
                    client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

                    message_text = get_text(client_lang, 'ticket_cancelled_msg', ticket_id=ticket_id)
                    asyncio.run_coroutine_threadsafe(
                        bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                        dp.loop
                    )
                    logging.info(f"Telegram cancellation notification sent to client {client_tg_id} for ticket {ticket_id}.")
            except Exception as e:
                conn.rollback()
                logging.error(f"Operator {operator_info['username']} failed to cancel ticket {ticket_id}: {e}")
                await callback_query.answer(f"Error cancelling ticket: {e}")


    @router.callback_query(F.data.startswith('no_show_ticket_'))
    async def cb_no_show_ticket(callback_query: types.CallbackQuery, branch_id: int):
        """Callback to mark a ticket as 'no_show'."""
        ticket_id = callback_query.data.split('_')[3]
        with app.app_context():
            conn = get_db()
            operator_info = conn.execute("SELECT id FROM users WHERE telegram_user_id = ?", (callback_query.from_user.id,)).fetchone()

            if not operator_info:
                await callback_query.answer(get_text('uz_lat', 'unauthorized_action'))
                return

            c = conn.cursor()
            ticket_check = c.execute("SELECT id, client_telegram_user_id FROM tickets WHERE id = ? AND operator_id = ? AND branch_id = ? AND status = 'called'",
                                     (ticket_id, operator_info['id'], branch_id)).fetchone()
            if not ticket_check:
                await callback_query.answer(get_text('uz_lat', 'ticket_not_callable'))
                return

            client_tg_id = ticket_check['client_telegram_user_id']

            try:
                c.execute("UPDATE tickets SET status = 'no_show', finish_time = CURRENT_TIMESTAMP WHERE id = ?", (ticket_id,))
                if client_tg_id:
                    c.execute("UPDATE users SET current_ticket_id = NULL WHERE telegram_user_id = ? AND current_ticket_id = ?",
                              (client_tg_id, ticket_id))
                conn.commit()
                socketio.emit('ticket_no_show', {'ticket_id': ticket_id, 'status': 'no_show', 'branch_id': branch_id}, room=f'display_{branch_id}')
                socketio.emit('ticket_no_show', {'ticket_id': ticket_id, 'status': 'no_show', 'branch_id': branch_id}, room=f'operator_{operator_info["id"]}_{branch_id}')
                socketio.emit('ticket_no_show', {'ticket_id': ticket_id, 'status': 'no_show', 'branch_id': branch_id}, room=f'operator_branch_{branch_id}')
                await callback_query.message.edit_text(get_text('uz_lat', 'ticket_no_show_msg', ticket_id=ticket_id), parse_mode="Markdown")
                await callback_query.answer()

                if bot and client_tg_id:
                    # Get the client's preferred language from the 'users' table
                    client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
                    client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

                    message_text = get_text(client_lang, 'ticket_no_show_msg', ticket_id=ticket_id)
                    asyncio.run_coroutine_threadsafe(
                        bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                        dp.loop
                    )
                    logging.info(f"Telegram no-show notification sent to client {client_tg_id} for ticket {ticket_id}.")
            except Exception as e:
                conn.rollback()
                logging.error(f"Operator {operator_info['username']} failed to mark ticket {ticket_id} as no-show: {e}")
                await callback_query.answer(f"Error marking ticket as no-show: {e}")


    @router.callback_query(F.data.startswith('skip_ticket_'))
    async def cb_skip_ticket(callback_query: types.CallbackQuery, branch_id: int):
        """Callback to mark a ticket as 'skipped'."""
        ticket_id = callback_query.data.split('_')[2]
        with app.app_context():
            conn = get_db()
            operator_info = conn.execute("SELECT id FROM users WHERE telegram_user_id = ?", (callback_query.from_user.id,)).fetchone()

            if not operator_info:
                await callback_query.answer(get_text('uz_lat', 'unauthorized_action'))
                return

            c = conn.cursor()
            ticket_check = c.execute("SELECT id, client_telegram_user_id FROM tickets WHERE id = ? AND operator_id = ? AND branch_id = ? AND status = 'called'",
                                     (ticket_id, operator_info['id'], branch_id)).fetchone()
            if not ticket_check:
                await callback_query.answer(get_text('uz_lat', 'ticket_not_callable'))
                return

            client_tg_id = ticket_check['client_telegram_user_id']

            try:
                c.execute("UPDATE tickets SET status = 'waiting', operator_id = NULL WHERE id = ?", (ticket_id,))
                # For skipped tickets, we do NOT clear current_ticket_id, as they are still in the queue.
                conn.commit()
                socketio.emit('ticket_skipped', {'ticket_id': ticket_id, 'status': 'waiting', 'branch_id': branch_id}, room=f'display_{branch_id}')
                socketio.emit('ticket_skipped', {'ticket_id': ticket_id, 'status': 'waiting', 'branch_id': branch_id}, room=f'operator_{operator_info["id"]}_{branch_id}')
                socketio.emit('ticket_skipped', {'ticket_id': ticket_id, 'status': 'waiting', 'branch_id': branch_id}, room=f'operator_branch_{branch_id}')
                await callback_query.message.edit_text(get_text('uz_lat', 'ticket_skipped_msg', ticket_id=ticket_id), parse_mode="Markdown")
                await callback_query.answer()

                if bot and client_tg_id:
                    # Get the client's preferred language from the 'users' table
                    client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
                    client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'

                    message_text = get_text(client_lang, 'ticket_skipped_msg', ticket_id=ticket_id)
                    asyncio.run_coroutine_threadsafe(
                        bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                        dp.loop
                    )
                    logging.info(f"Telegram skipped notification sent to client {client_tg_id} for ticket {ticket_id}.")
            except Exception as e:
                conn.rollback()
                logging.error(f"Operator {operator_info['username']} failed to skip ticket {ticket_id}: {e}")
                await callback_query.answer(f"Error skipping ticket: {e}")

    @router.callback_query(F.data.startswith('redirect_ticket_prompt_'))
    async def cb_redirect_ticket_prompt(callback_query: types.CallbackQuery, state: FSMContext, branch_id: int):
        """Prompts operator to select a new service for redirecting a ticket."""
        ticket_id = callback_query.data.split('_')[3] # redirect_ticket_prompt_TICKET_ID
        await state.update_data(ticket_to_redirect_id=ticket_id)

        with app.app_context():
            conn = get_db()
            # Get services from the same branch, excluding the current service of the ticket (optional)
            current_ticket_service_id = conn.execute("SELECT service_id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
            services = conn.execute(
                "SELECT id, name_uz_lat FROM services WHERE branch_id = ? AND is_active = 1 AND id != ?",
                (branch_id, current_ticket_service_id['service_id'] if current_ticket_service_id else -1) # -1 if no service_id found
            ).fetchall()

        if not services:
            await callback_query.message.edit_text(get_text('uz_lat', 'no_other_services_to_redirect'))
            await state.clear()
            return

        keyboard_buttons = [[types.InlineKeyboardButton(text=svc['name_uz_lat'], callback_data=f"redirect_to_svc_{svc['id']}")] for svc in services]
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)
        await callback_query.message.edit_text(get_text('uz_lat', 'select_service_to_redirect'), reply_markup=keyboard)
        await state.set_state(ClientForm.RedirectingTicket) # Using ClientForm for simplicity, can be OperatorForm
        await callback_query.answer()

    @router.callback_query(ClientForm.RedirectingTicket, F.data.startswith('redirect_to_svc_'))
    async def cb_redirect_ticket_to_service(callback_query: types.CallbackQuery, state: FSMContext, branch_id: int):
        """Redirects the ticket to the selected new service."""
        new_service_id = int(callback_query.data.split('_')[3]) # redirect_to_svc_SERVICE_ID
        user_data = await state.get_data()
        ticket_id = user_data.get('ticket_to_redirect_id')

        if not ticket_id:
            await callback_query.message.edit_text(get_text('uz_lat', 'error_redirecting_ticket_state'))
            await state.clear()
            return

        with app.app_context():
            conn = get_db()
            operator_info = conn.execute("SELECT id FROM users WHERE telegram_user_id = ?", (callback_query.from_user.id,)).fetchone()
            if not operator_info:
                await callback_query.answer(get_text('uz_lat', 'unauthorized_action'))
                await state.clear()
                return

            operator_id = operator_info['id']

            ticket_check = conn.execute("SELECT id, client_telegram_user_id FROM tickets WHERE id = ? AND operator_id = ? AND branch_id = ? AND status = 'called'",
                                        (ticket_id, operator_id, branch_id)).fetchone()
            if not ticket_check:
                await callback_query.message.edit_text(get_text('uz_lat', 'ticket_not_callable_for_redirect'))
                await state.clear()
                return

            client_tg_id = ticket_check['client_telegram_user_id']
            new_service = conn.execute("SELECT name_uz_lat FROM services WHERE id = ? AND branch_id = ?", (new_service_id, branch_id)).fetchone()
            if not new_service:
                await callback_query.message.edit_text(get_text('uz_lat', 'new_service_not_found_for_redirect'))
                await state.clear()
                return

            try:
                c = conn.cursor()
                c.execute("""
                    UPDATE tickets SET status = 'waiting', service_id = ?, redirect_to_service_id = ?,
                    operator_id = NULL, redirect_time = CURRENT_TIMESTAMP, sort_order = NULL
                    WHERE id = ?
                """, (new_service_id, new_service_id, ticket_id)) # Reset sort_order so it goes to end of new queue
                conn.commit()

                socketio.emit('ticket_redirected', {
                    'ticket_id': ticket_id,
                    'new_service_id': new_service_id,
                    'new_service_name': new_service['name_uz_lat'],
                    'branch_id': branch_id
                }, room=f'display_{branch_id}')
                socketio.emit('ticket_redirected', {
                    'ticket_id': ticket_id,
                    'new_service_id': new_service_id,
                    'new_service_name': new_service['name_uz_lat'],
                    'branch_id': branch_id
                }, room=f'operator_{operator_id}_{branch_id}')
                socketio.emit('ticket_redirected', {
                    'ticket_id': ticket_id,
                    'new_service_id': new_service_id,
                    'new_service_name': new_service['name_uz_lat'],
                    'branch_id': branch_id
                }, room=f'operator_branch_{branch_id}')
                await callback_query.message.edit_text(get_text('uz_lat', 'ticket_redirected_success', new_service_name=new_service['name_uz_lat']), parse_mode="Markdown")

                if bot and client_tg_id:
                    client_lang_row = conn.execute("SELECT lang FROM users WHERE telegram_user_id = ?", (client_tg_id,)).fetchone()
                    client_lang = client_lang_row['lang'] if client_lang_row and client_lang_row['lang'] else 'uz_lat'
                    message_text = get_text(client_lang, 'ticket_redirected_msg',
                                            ticket_id=ticket_id,
                                            new_service_name=new_service['name_uz_lat'])
                    asyncio.run_coroutine_threadsafe(
                        bot.send_message(client_tg_id, message_text, parse_mode="Markdown"),
                        dp.loop
                    )
            except Exception as e:
                conn.rollback()
                logging.error(f"Operator {operator_info['username']} failed to redirect ticket {ticket_id} via bot: {e}")
                await callback_query.message.edit_text(get_text('uz_lat', 'error_redirecting_ticket'))
            finally:
                await state.clear()
            await callback_query.answer()

    @router.message(Command('my_queue'))
    async def cmd_operator_my_queue(message: types.Message, branch_id: int):
        """Displays the operator's current queue (tickets assigned to their services or called by them)."""
        with app.app_context():
            conn = get_db()
            operator_info = conn.execute("SELECT id, role FROM users WHERE telegram_user_id = ?", (message.from_user.id,)).fetchone()

            if not operator_info or operator_info['role'] not in ['operator', 'branch_admin', 'super_admin']:
                await message.answer(get_text('uz_lat', 'unauthorized_operator_access'))
                return
            operator_id = operator_info['id']

            tickets = conn.execute("""
                SELECT t.id, t.number, s.name_uz_lat as service_name, t.status,
                       CASE WHEN client_u.is_vip = 1 THEN '(VIP) ' ELSE '' END || COALESCE(client_u.username, 'N/A') as client_name
                FROM tickets t
                JOIN services s ON t.service_id = s.id
                LEFT JOIN users op_assigned ON s.operator_id = op_assigned.id
                LEFT JOIN users client_u ON t.client_telegram_user_id = client_u.telegram_user_id
                WHERE t.branch_id = ?
                      AND (op_assigned.id = ? OR t.operator_id = ?) -- Assigned to this operator's service OR called by this operator
                      AND t.status IN ('waiting', 'called', 'redirected')
                ORDER BY t.status DESC, CASE WHEN client_u.is_vip = 1 THEN 0 ELSE 1 END ASC, t.sort_order ASC NULLS LAST, t.start_time ASC
                LIMIT 10
            """, (branch_id, operator_id, operator_id)).fetchall()

        if not tickets:
            await message.answer(get_text('uz_lat', 'no_tickets_in_your_queue'))
            return

        response_text = get_text('uz_lat', 'your_current_queue_title') + "\n"
        for ticket in tickets:
            response_text += get_text('uz_lat', 'operator_queue_item',
                number=ticket['number'],
                service_name=ticket['service_name'],
                status=get_text('uz_lat', f"status_{ticket['status']}"),
                client_name=ticket['client_name']
            ) + "\n"
        await message.answer(response_text, parse_mode="Markdown")

    @router.message(Command('stats'))
    async def cmd_operator_stats(message: types.Message, branch_id: int):
        """Displays daily statistics for the operator."""
        with app.app_context():
            conn = get_db()
            operator_info = conn.execute("SELECT id, role FROM users WHERE telegram_user_id = ?", (message.from_user.id,)).fetchone()

            if not operator_info or operator_info['role'] not in ['operator', 'branch_admin', 'super_admin']:
                await message.answer(get_text('uz_lat', 'unauthorized_operator_access'))
                return
            operator_id = operator_info['id']

            today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = today_start + timedelta(days=1)

            tickets_finished = conn.execute("""
                SELECT COUNT(*) FROM tickets
                WHERE operator_id = ? AND branch_id = ? AND status = 'finished'
                AND finish_time BETWEEN ? AND ?
            """, (operator_id, branch_id, today_start, today_end)).fetchone()[0]

            avg_service_time_row = conn.execute("""
                SELECT AVG(strftime('%s', finish_time) - strftime('%s', call_time)) FROM tickets
                WHERE operator_id = ? AND branch_id = ? AND status = 'finished'
                AND finish_time BETWEEN ? AND ? AND call_time IS NOT NULL
            """, (operator_id, branch_id, today_start, today_end)).fetchone()
            avg_service_time = int(avg_service_time_row[0]) if avg_service_time_row and avg_service_time_row[0] is not None else 0


        stats_text = get_text('uz_lat', 'operator_stats_title') + "\n" + \
                     get_text('uz_lat', 'operator_stats_finished_today', count=tickets_finished) + "\n" + \
                     get_text('uz_lat', 'operator_stats_avg_service_time', time=avg_service_time)

        await message.answer(stats_text, parse_mode="Markdown")

    class SetAvailabilityStates(StatesGroup):
        SettingAvailability = State()
        SettingStartTime = State()
        SettingEndTime = State()

    @router.message(Command('set_availability'))
    async def cmd_set_availability_prompt(message: types.Message, state: FSMContext, branch_id: int):
        with app.app_context():
            conn = get_db()
            operator_info = conn.execute("SELECT id, role, is_available FROM users WHERE telegram_user_id = ?", (message.from_user.id,)).fetchone()

            if not operator_info or operator_info['role'] not in ['operator', 'branch_admin', 'super_admin']:
                await message.answer(get_text('uz_lat', 'unauthorized_operator_access'))
                return

        current_status = get_text('uz_lat', 'status_available') if operator_info['is_available'] else get_text('uz_lat', 'status_unavailable')
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=[
            [types.InlineKeyboardButton(text=get_text('uz_lat', 'set_available_btn'), callback_data="set_avail_true")],
            [types.InlineKeyboardButton(text=get_text('uz_lat', 'set_unavailable_btn'), callback_data="set_avail_false")],
            [types.InlineKeyboardButton(text=get_text('uz_lat', 'set_schedule_btn'), callback_data="set_avail_schedule")]
        ])
        await message.answer(get_text('uz_lat', 'set_availability_prompt', current_status=current_status), reply_markup=keyboard)
        await state.set_state(SetAvailabilityStates.SettingAvailability)


    @router.callback_query(SetAvailabilityStates.SettingAvailability, F.data.startswith("set_avail_"))
    async def cb_set_availability_status(callback_query: types.CallbackQuery, state: FSMContext, branch_id: int):
        action = callback_query.data.split("_")[2] # true, false, or schedule

        with app.app_context():
            conn = get_db()
            operator_info = conn.execute("SELECT id FROM users WHERE telegram_user_id = ?", (callback_query.from_user.id,)).fetchone()
            if not operator_info:
                await callback_query.answer(get_text('uz_lat', 'unauthorized_action'), show_alert=True)
                await state.clear()
                return
            operator_id = operator_info['id']

            if action == "true":
                conn.execute("UPDATE users SET is_available = 1, available_start_time = NULL, available_end_time = NULL WHERE id = ?", (operator_id,))
                conn.commit()
                await callback_query.message.edit_text(get_text('uz_lat', 'availability_set_to_available'))
                await state.clear()
            elif action == "false":
                conn.execute("UPDATE users SET is_available = 0, available_start_time = NULL, available_end_time = NULL WHERE id = ?", (operator_id,))
                conn.commit()
                await callback_query.message.edit_text(get_text('uz_lat', 'availability_set_to_unavailable'))
                await state.clear()
            elif action == "schedule":
                await callback_query.message.edit_text(get_text('uz_lat', 'enter_start_time_prompt'))
                await state.set_state(SetAvailabilityStates.SettingStartTime)
        await callback_query.answer()

    @router.message(SetAvailabilityStates.SettingStartTime)
    async def process_availability_start_time(message: types.Message, state: FSMContext, branch_id: int):
        try:
            # Basic validation, can be improved with regex or dateutil.parser
            start_time = datetime.strptime(message.text, "%H:%M").time()
            await state.update_data(start_time=start_time.strftime("%H:%M"))
            await message.answer(get_text('uz_lat', 'enter_end_time_prompt'))
            await state.set_state(SetAvailabilityStates.SettingEndTime)
        except ValueError:
            await message.answer(get_text('uz_lat', 'invalid_time_format_prompt'))
            # Stay in the same state to allow re-entry

    @router.message(SetAvailabilityStates.SettingEndTime)
    async def process_availability_end_time(message: types.Message, state: FSMContext, branch_id: int):
        try:
            end_time = datetime.strptime(message.text, "%H:%M").time()
            user_data = await state.get_data()
            start_time_str = user_data.get('start_time')

            if not start_time_str:
                await message.answer(get_text('uz_lat', 'error_start_time_not_set'))
                await state.clear()
                return

            start_time = datetime.strptime(start_time_str, "%H:%M").time()
            if end_time <= start_time:
                await message.answer(get_text('uz_lat', 'end_time_before_start_prompt'))
                return # Stay in state for re-entry

            with app.app_context():
                conn = get_db()
                operator_info = conn.execute("SELECT id FROM users WHERE telegram_user_id = ?", (message.from_user.id,)).fetchone()
                if not operator_info:
                    await message.answer(get_text('uz_lat', 'unauthorized_action'))
                    await state.clear()
                    return
                operator_id = operator_info['id']

                # Store as full datetime for today for easier comparison, or just time strings
                today = datetime.now().date()
                full_start_time = datetime.combine(today, start_time)
                full_end_time = datetime.combine(today, end_time)

                conn.execute("UPDATE users SET is_available = 1, available_start_time = ?, available_end_time = ? WHERE id = ?",
                             (full_start_time.isoformat(), full_end_time.isoformat(), operator_id))
                conn.commit()
            await message.answer(get_text('uz_lat', 'availability_schedule_set', start_time=start_time_str, end_time=end_time.strftime("%H:%M")))
            await state.clear()
        except ValueError:
            await message.answer(get_text('uz_lat', 'invalid_time_format_prompt'))
            # Stay in the same state to allow re-entry
        except Exception as e:
            logging.error(f"Error setting availability schedule: {e}")
            await message.answer(get_text('uz_lat', 'error_setting_schedule'))
            await state.clear()

    # Generic callback_query handler for unhandled callbacks (e.g., after state clear)
    @router.callback_query()
    async def unhandled_callback_query(callback_query: types.CallbackQuery):
        logging.warning(f"Unhandled callback query: {callback_query.data} from user {callback_query.from_user.id}")
        await callback_query.answer(get_text('uz_lat', 'action_expired_or_invalid'), show_alert=True)
        try:
            # Attempt to remove the inline keyboard if the message is still accessible
            await callback_query.message.edit_reply_markup(reply_markup=None)
        except Exception:
            pass # Ignore if message can't be edited (e.g., too old)

# --- Telegram Bot Polling Function ---
async def run_telegram_bot():
    if dp and bot:
        register_aiogram_handlers(dp)
        logging.info("Starting Telegram bot polling...")
        try:
            await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
        except asyncio.CancelledError:
            logging.info("Telegram bot polling was cancelled.")
        except Exception as e:
            logging.error(f"Telegram bot polling loop error: {e}", exc_info=True)
        finally:
            logging.info("Telegram bot polling loop finishing. Cleaning up...")
            if bot and hasattr(bot, 'session') and bot.session and not bot.session.closed:
                try:
                    await bot.session.close()
                    logging.info("Telegram bot session closed successfully.")
                except Exception as e_close:
                    logging.error(f"Error closing bot session: {e_close}", exc_info=True)
            # If using persistent storage that needs explicit closing:
            # if dp and hasattr(dp, 'storage') and hasattr(dp.storage, 'close'):
            #     try:
            #         await dp.storage.close()
            #         logging.info("Telegram bot storage closed successfully.")
            #     except Exception as e_storage_close:
            #         logging.error(f"Error closing bot storage: {e_storage_close}", exc_info=True)
            logging.info("Telegram bot polling stopped and cleaned up.")
    else:
        logging.warning("Telegram bot (dp or bot) is not initialized. Polling not started.")

def bot_thread_target():
    try:
        asyncio.run(run_telegram_bot())
    except KeyboardInterrupt:
        logging.info("Bot thread target interrupted by KeyboardInterrupt.")
    except SystemExit:
        logging.info("Bot thread target received SystemExit.")
    except Exception as e:
        logging.error(f"Exception in bot_thread_target: {e}", exc_info=True)

# --- Background Task for Cleaning Old Tickets ---
def clean_old_tickets():
    """Periodically cleans old, non-active tickets from the database."""
    days_to_keep = int(os.getenv("OLD_TICKET_CLEANUP_DAYS", 7))
    cleanup_interval_hours = int(os.getenv("OLD_TICKET_CLEANUP_INTERVAL_HOURS", 24))

    with app.app_context():
        conn = get_db()
        c = conn.cursor()
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            # Delete tickets that are 'finished', 'cancelled', 'no_show' and older than cutoff_date
            # Keep 'waiting', 'called', 'redirected', 'skipped' as they might still be relevant or part of an ongoing issue
            c.execute("""
                DELETE FROM tickets
                WHERE status IN ('finished', 'cancelled', 'no_show')
                AND start_time < ?
            """, (cutoff_date,))
            deleted_count = c.rowcount
            conn.commit()
            if deleted_count > 0:
                logging.info(f"Cleaned up {deleted_count} old tickets older than {cutoff_date.strftime('%Y-%m-%d')}.")
            else:
                logging.info(f"No old tickets to clean up older than {cutoff_date.strftime('%Y-%m-%d')}.")

            # Clean up associated chat messages for deleted tickets (orphaned)
            # This requires a more complex query or doing it before deleting tickets
            # For simplicity, we'll assume ON DELETE CASCADE handles chat_messages if ticket_id is FK.
            # If not, an explicit delete for chat_messages and feedback would be needed here.
            # Example: DELETE FROM chat_messages WHERE ticket_id NOT IN (SELECT id FROM tickets);

        except Exception as e:
            conn.rollback()
            logging.error(f"Error during old ticket cleanup: {e}")
        # finally: # Managed by teardown_appcontext
        #     conn.close()

    # Schedule the next run
    Timer(cleanup_interval_hours * 3600, clean_old_tickets).start()
    logging.info(f"Next old ticket cleanup scheduled in {cleanup_interval_hours} hours.")


# --- Main Application Execution ---
if __name__ == '__main__':
    with app.app_context():
        init_db() # Initialize database schema and superadmin

    # Start Telegram bot in a separate thread only in the main Werkzeug process or if not in debug mode
    # This helps prevent the reloader from starting multiple bot instances.
    should_run_background_tasks = False
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true": # Executing in the reloader's child process
        should_run_background_tasks = True
        logging.info("Running in Werkzeug reloader child process. Background tasks will be started.")
    elif not DEBUG_MODE: # Not in debug mode (reloader likely off)
        should_run_background_tasks = True
        logging.info("Running without Werkzeug reloader or debug mode is off. Background tasks will be started.")
    else:
        logging.info("Running in Werkzeug reloader parent process. Background tasks will NOT be started here.")

    if should_run_background_tasks:
        if TELEGRAM_BOT_TOKEN and dp and bot:
            logging.info("Preparing to start Telegram bot thread.")
            bot_thread = Thread(target=bot_thread_target, daemon=True)
            bot_thread.start()
        else:
            logging.warning("Telegram bot will not run as TELEGRAM_BOT_TOKEN is not set or bot failed to initialize.")

        # Start periodic cleanup of old tickets
        initial_cleanup_delay_seconds = 60 # Start first cleanup 1 minute after app start
        Timer(initial_cleanup_delay_seconds, clean_old_tickets).start()
        logging.info(f"Initial old ticket cleanup scheduled in {initial_cleanup_delay_seconds} seconds.")
    else:
        # This block executes if it's the parent process of the reloader
        pass


    logging.info(f"Flask app starting on {FLASK_RUN_HOST}:{FLASK_RUN_PORT} with debug_mode={DEBUG_MODE}")
    socketio.run(app, host=FLASK_RUN_HOST, port=FLASK_RUN_PORT, debug=DEBUG_MODE, use_reloader=False, log_output=False)