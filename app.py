import os
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, abort, send_file
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from flask_session import Session
import sqlite3
from datetime import datetime
import secrets
import logging
import getpass
from dotenv import load_dotenv
import qrcode
from PIL import Image
import uuid
import pandas as pd
from io import BytesIO
from werkzeug.utils import secure_filename
import base64

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
Session(app)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

# Configuration
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:5000")
DB_PATH = os.getenv("DB_PATH", "regoffice.db")
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'mp4', 'jpg', 'jpeg', 'png'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    filename='app.log',
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS categories (
                 id INTEGER PRIMARY KEY, 
                 name TEXT, 
                 parent_id INTEGER, 
                 FOREIGN KEY(parent_id) REFERENCES categories(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS services (
                 id INTEGER PRIMARY KEY, 
                 name TEXT, 
                 category_id INTEGER, 
                 FOREIGN KEY(category_id) REFERENCES categories(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS operators (
                 id INTEGER PRIMARY KEY, 
                 name TEXT, 
                 password TEXT, 
                 status TEXT,
                 operator_number INTEGER UNIQUE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS operator_services (
                 operator_id INTEGER, 
                 service_id INTEGER, 
                 FOREIGN KEY(operator_id) REFERENCES operators(id) ON DELETE CASCADE
                 FOREIGN KEY(service_id) REFERENCES services(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS tickets (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 number TEXT, 
                 service_id INTEGER, 
                 status TEXT, 
                 operator_id INTEGER, 
                 created_at TEXT, 
                 finished_at TEXT, 
                 kiosk_id INTEGER,
                 FOREIGN KEY(service_id) REFERENCES services(id), 
                 FOREIGN KEY(operator_id) REFERENCES operators(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 operator_id INTEGER, 
                 content TEXT, 
                 timestamp TEXT, 
                 FOREIGN KEY(operator_id) REFERENCES operators(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS admin_users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS evaluations (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 ticket_number TEXT,
                 operator_id INTEGER,
                 rating INTEGER,
                 comment TEXT,
                 created_at TEXT,
                 FOREIGN KEY(ticket_number) REFERENCES tickets(number),
                 FOREIGN KEY(operator_id) REFERENCES operators(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS disputes (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 ticket_number TEXT,
                 operator_id INTEGER,
                 comment TEXT,
                 created_at TEXT,
                 status TEXT,
                 FOREIGN KEY(ticket_number) REFERENCES tickets(number),
                 FOREIGN KEY(operator_id) REFERENCES operators(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS chats (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 ticket_number TEXT,
                 sender_type TEXT,
                 sender_id INTEGER,
                 content TEXT,
                 timestamp TEXT,
                 FOREIGN KEY(ticket_number) REFERENCES tickets(number))''')
    c.execute('''CREATE TABLE IF NOT EXISTS media (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 type TEXT NOT NULL,
                 filename TEXT NOT NULL,
                 title TEXT,
                 description TEXT,
                 display_order INTEGER DEFAULT 0,
                 created_at TEXT NOT NULL,
                 uploaded_by INTEGER,
                 FOREIGN KEY(uploaded_by) REFERENCES admin_users(id))''')
    conn.commit()

    # Create default admin if none exists
    c.execute("SELECT COUNT(*) FROM admin_users")
    if c.fetchone()[0] == 0:
        username = input("Enter admin username: ")
        password = getpass.getpass("Enter admin password: ")
        c.execute("INSERT INTO admin_users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        logging.info(f"Created admin user: {username}")

    # Migrate operators table to add operator_number
    try:
        c.execute("ALTER TABLE operators ADD COLUMN operator_number INTEGER UNIQUE")
        conn.commit()
        logging.info("Added operator_number column to operators table")
    except sqlite3.OperationalError as e:
        logging.info(f"Operators table migration skipped: {e}")

    conn.close()

# Login required decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'operator_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Get category depth
def get_category_depth(category_id):
    conn = sqlite3.connect(DB_PATH)
    depth = 0
    current_id = category_id
    c = conn.cursor()
    while current_id:
        c.execute("SELECT parent_id FROM categories WHERE id = ?", (current_id,))
        result = c.fetchone()
        if not result or not result[0]:
            break
        current_id = result[0]
        depth += 1
        if depth >= 10:
            return 10
    conn.close()
    return depth

@app.route('/')
def index():
    return render_template('index.html', server_url=SERVER_URL)

@app.route('/categories', methods=['GET'])
def get_categories():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, parent_id FROM categories WHERE parent_id IS NULL")
    categories = [{"id": row[0], "name": row[1], "isCategory": True, "isSubcategory": False} for row in c.fetchall()]
    conn.close()
    logging.info(f"Fetched {len(categories)} top-level categories")
    return jsonify(categories)

@app.route('/services/<int:category_id>', methods=['GET'])
def get_services(category_id):
    page = int(request.args.get('page', 1))
    per_page = 10
    offset = (page - 1) * per_page
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, parent_id FROM categories WHERE parent_id = ? LIMIT ? OFFSET ?",
              (category_id, per_page, offset))
    subcategories = [{"id": row[0], "name": row[1], "isCategory": True, "isSubcategory": True} for row in c.fetchall()]
    c.execute("SELECT COUNT(*) FROM categories WHERE parent_id = ?", (category_id,))
    total_subcategories = c.fetchone()[0]
    c.execute("SELECT id, name, category_id FROM services WHERE category_id = ? LIMIT ? OFFSET ?",
              (category_id, per_page, offset))
    services = [{"id": row[0], "name": row[1], "isCategory": False, "isSubcategory": False} for row in c.fetchall()]
    c.execute("SELECT COUNT(*) FROM services WHERE category_id = ?", (category_id,))
    total_services = c.fetchone()[0]
    items = subcategories + services
    total = total_subcategories + total_services
    conn.close()
    logging.info(f"Fetched {len(items)} items for category {category_id}, page {page}")
    return jsonify({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page
    })

@app.route('/get_ticket', methods=['POST'])
def get_ticket():
    data = request.get_json()
    service_id = data.get('service_id')
    lang = data.get('lang', 'uz_lat')
    kiosk_id = data.get('kiosk_id', 1)
    logging.info(f"get_ticket: service_id={service_id}, lang={lang}, kiosk_id={kiosk_id}")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT name, category_id FROM services WHERE id = ?", (service_id,))
    service = c.fetchone()
    if not service:
        conn.close()
        logging.error(f"Service {service_id} not found")
        return jsonify({"error": "Service not found"}), 404
    service_name = service[0]
    c.execute("SELECT COUNT(*) FROM tickets WHERE service_id = ? AND DATE(created_at) = DATE('now')", (service_id,))
    count = c.fetchone()[0] + 1
    ticket_number = f"{service_id:02d}-{count:03d}"
    c.execute("SELECT AVG(strftime('%s', finished_at) - strftime('%s', created_at)) / 60 FROM tickets WHERE service_id = ? AND finished_at IS NOT NULL", (service_id,))
    avg_time = c.fetchone()[0] or 5
    wait_time = round(avg_time * count)
    c.execute("SELECT operator_id FROM operator_services WHERE service_id = ? LIMIT 1", (service_id,))
    operator = c.fetchone()
    operator_id = operator[0] if operator else None
    operator_name = None
    operator_number = None
    if operator_id:
        c.execute("SELECT name, operator_number FROM operators WHERE id = ?", (operator_id,))
        op_data = c.fetchone()
        operator_name = op_data[0]
        operator_number = op_data[1]
    created_at = datetime.now().isoformat()
    c.execute("INSERT INTO tickets (number, service_id, status, operator_id, created_at, kiosk_id) VALUES (?, ?, 'waiting', ?, ?, ?)",
              (ticket_number, service_id, operator_id, created_at, kiosk_id))
    ticket_id = c.lastrowid
    conn.commit()
    status_url = f"{SERVER_URL}/ticket/{ticket_number}"
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(status_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    qr_img.save(buffered, format="PNG")
    qr_data = base64.b64encode(buffered.getvalue()).decode('utf-8')
    socketio.emit('new_ticket', {'ticket': ticket_number, 'service_id': service_id, 'operator_id': operator_id})
    logging.info(f"Created ticket: {ticket_number}, service: {service_id}, operator: {operator_id or 'None'}")
    conn.close()
    return jsonify({
        "ticket": ticket_number,
        "ticket_id": ticket_id,
        "wait_time": wait_time,
        "service_name": service_name,
        "operator_id": operator_id,
        "operator_name": operator_name,
        "operator_number": operator_number,
        "created_at": created_at,
        "status_url": status_url,
        "qr_data": qr_data
    })

@app.route('/ticket_status/<ticket_number>', methods=['GET'])
def ticket_status(ticket_number):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT t.id, t.number, t.service_id, t.status, t.operator_id, t.created_at, 
               s.name as service_name, o.name as operator_name, o.operator_number
        FROM tickets t
        LEFT JOIN services s ON t.service_id = s.id
        LEFT JOIN operators o ON t.operator_id = o.id
        WHERE t.number = ?
    """, (ticket_number,))
    ticket = c.fetchone()
    if not ticket:
        conn.close()
        logging.error(f"Ticket {ticket_number} not found")
        return jsonify({"error": "Ticket not found"}), 404
    c.execute("""
        SELECT COUNT(*) FROM tickets 
        WHERE service_id = ? AND status = 'waiting' AND created_at <= ?
    """, (ticket[2], ticket[5]))
    position = c.fetchone()[0] + 1 if ticket[3] == 'waiting' else 0
    c.execute("""
        SELECT AVG(strftime('%s', finished_at) - strftime('%s', created_at)) / 60 
        FROM tickets WHERE service_id = ? AND finished_at IS NOT NULL
    """, (ticket[2],))
    avg_time = c.fetchone()[0] or 5
    wait_time = round(avg_time * position) if position > 0 else 0
    conn.close()
    return jsonify({
        "ticket_id": ticket[0],
        "ticket_number": ticket[1],
        "service_name": ticket[6],
        "status": ticket[3],
        "operator_name": ticket[7],
        "operator_number": ticket[8],
        "position": position,
        "wait_time": wait_time
    })

@app.route('/ticket/<ticket_number>')
def ticket_page(ticket_number):
    return render_template('ticket_status.html', ticket_number=ticket_number, server_url=SERVER_URL)

@app.route('/dispute/<ticket_number>', methods=['GET', 'POST'])
def dispute(ticket_number):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, operator_id, status FROM tickets WHERE number = ?", (ticket_number,))
    ticket = c.fetchone()
    if not ticket:
        conn.close()
        return render_template('error.html', message="Ticket not found", server_url=SERVER_URL), 404
    if request.method == 'POST':
        comment = request.form.get('comment')
        created_at = datetime.now().isoformat()
        c.execute("INSERT INTO disputes (ticket_number, operator_id, comment, created_at, status) VALUES (?, ?, ?, ?, 'open')",
                  (ticket_number, ticket[1], comment, created_at))
        conn.commit()
        logging.info(f"Dispute filed for ticket {ticket_number}")
        conn.close()
        return redirect(url_for('ticket_page', ticket_number=ticket_number))
    conn.close()
    return render_template('dispute.html', ticket_number=ticket_number, server_url=SERVER_URL)

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    ticket_id = request.form.get('ticket_id')
    rating = request.form.get('rating')
    comment = request.form.get('comment')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT number, operator_id FROM tickets WHERE id = ?", (ticket_id,))
    ticket = c.fetchone()
    if not ticket:
        conn.close()
        return jsonify({"error": "Ticket not found"}), 404
    ticket_number, operator_id = ticket
    created_at = datetime.now().isoformat()
    c.execute("INSERT INTO evaluations (ticket_number, operator_id, rating, comment, created_at) VALUES (?, ?, ?, ?, ?)",
              (ticket_number, operator_id, rating, comment, created_at))
    conn.commit()
    logging.info(f"Feedback submitted for ticket {ticket_number}: rating={rating}")
    conn.close()
    return redirect(url_for('ticket_page', ticket_number=ticket_number))

@app.route('/chat/<ticket_number>')
def chat(ticket_number):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM tickets WHERE number = ?", (ticket_number,))
    ticket = c.fetchone()
    conn.close()
    if not ticket:
        return render_template('error.html', message="Invalid ticket", server_url=SERVER_URL), 404
    return render_template('chat.html', ticket_id=ticket[0], server_url=SERVER_URL)

@app.route('/export_report', methods=['POST'])
@admin_required
def export_report():
    data = request.get_json()
    operator_id = data.get('operator_id')
    service_id = data.get('service_id')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    report_type = data.get('report_type', 'overall')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = """
        SELECT t.number, s.name as service_name, o.name as operator_name, o.operator_number,
               t.status, t.created_at, t.finished_at, e.rating, e.comment, d.comment as dispute_comment
        FROM tickets t
        LEFT JOIN services s ON t.service_id = s.id
        LEFT JOIN operators o ON t.operator_id = o.id
        LEFT JOIN evaluations e ON t.number = e.ticket_number
        LEFT JOIN disputes d ON t.number = d.ticket_number
        WHERE 1=1
    """
    params = []
    if operator_id:
        query += " AND t.operator_id = ?"
        params.append(operator_id)
    if service_id:
        query += " AND t.service_id = ?"
        params.append(service_id)
    if start_date and end_date:
        query += " AND t.created_at BETWEEN ? AND ?"
        params.extend([start_date, end_date])
    c.execute(query, params)
    overall_data = pd.DataFrame(c.fetchall(), columns=[
        'Ticket Number', 'Service Name', 'Operator Name', 'Operator Number', 'Status',
        'Created At', 'Finished At', 'Rating', 'Comment', 'Dispute Comment'
    ])
    c.execute(query, params)
    monthly_data = pd.DataFrame(c.fetchall(), columns=[
        'Ticket Number', 'Service Name', 'Operator Name', 'Operator Number', 'Status',
        'Created At', 'Finished At', 'Rating', 'Comment', 'Dispute Comment'
    ])
    monthly_data['Created At'] = pd.to_datetime(monthly_data['Created At'])
    monthly_data['Month'] = monthly_data['Created At'].dt.to_period('M')
    monthly_summary = monthly_data.groupby(['Month', 'Operator Name', 'Operator Number', 'Service Name', 'Status']).size().unstack(fill_value=0)
    operator_query = """
        SELECT o.name, o.operator_number, COUNT(t.number) as tickets, AVG(e.rating) as avg_rating,
               COUNT(d.id) as disputes
        FROM operators o
        LEFT JOIN tickets t ON o.id = t.operator_id
        LEFT JOIN evaluations e ON t.number = e.ticket_number
        LEFT JOIN disputes d ON t.number = d.ticket_number
        WHERE 1=1
    """
    operator_params = []
    if start_date and end_date:
        operator_query += " AND t.created_at BETWEEN ? AND ?"
        operator_params.extend([start_date, end_date])
    operator_query += " GROUP BY o.id, o.name, o.operator_number"
    c.execute(operator_query, operator_params)
    operator_data = pd.DataFrame(c.fetchall(), columns=['Operator Name', 'Operator Number', 'Tickets', 'Avg Rating', 'Disputes'])
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        overall_data.to_excel(writer, sheet_name='Overall', index=False)
        monthly_summary.to_excel(writer, sheet_name='Monthly')
        operator_data.to_excel(writer, sheet_name='Operator Stats')
    output.seek(0)
    conn.close()
    logging.info(f"Generated report: type={report_type}, operator={operator_id or 'all'}, service={service_id or 'all'}")
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    )

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id FROM admin_users WHERE username = ? AND password = ?", (username, password))
        admin = c.fetchone()
        conn.close()
        if admin:
            session['admin_id'] = admin[0]
            logging.info(f"Admin {username} logged in")
            return redirect(url_for('admin'))
        else:
            logging.warning(f"Failed admin login attempt for {username}")
            return render_template('admin_login.html', error="Invalid username or password", server_url=SERVER_URL)
    return render_template('admin_login.html', server_url=SERVER_URL)

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_id', None)
    logging.info("Admin logged out")
    return redirect(url_for('admin_login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        operator_id = request.form.get('operator_id')
        password = request.form.get('password')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, password FROM operators WHERE id = ? AND password = ?", (operator_id, password))
        operator = c.fetchone()
        conn.close()
        if operator:
            session['operator_id'] = operator[0]
            logging.info(f"Operator {operator_id} logged in")
            return redirect(url_for('operator'))
        else:
            logging.warning(f"Failed login attempt for operator {operator_id}")
            return render_template('login.html', error="Invalid ID or password", server_url=SERVER_URL)
    return render_template('login.html', server_url=SERVER_URL)

@app.route('/logout')
@login_required
def logout():
    operator_id = session.pop('operator_id', None)
    logging.info(f"Operator {operator_id} logged out")
    return redirect(url_for('login'))

@app.route('/operator')
@login_required
def operator():
    operator_id = session['operator_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, operator_number FROM operators")
    operators = c.fetchall()
    c.execute("SELECT number, status FROM tickets WHERE operator_id = ? AND status IN ('waiting', 'called')", (operator_id,))
    tickets = c.fetchall()
    c.execute("SELECT c.ticket_number, c.sender_type, c.content, c.timestamp FROM chats c WHERE c.ticket_number IN (SELECT number FROM tickets WHERE operator_id = ?) ORDER BY c.timestamp DESC LIMIT 50", (operator_id,))
    messages = c.fetchall()
    conn.close()
    return render_template('operator.html', operator_id=operator_id, operators=operators, tickets=tickets, messages=messages, server_url=SERVER_URL)

@app.route('/tablet/<int:operator_id>/data')
@login_required
def tablet_data(operator_id):
    if session['operator_id'] != operator_id:
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT number, status FROM tickets WHERE operator_id = ? AND status IN ('waiting', 'called')", (operator_id,))
    tickets = [{"number": row[0], "status": row[1]} for row in c.fetchall()]
    conn.close()
    return jsonify(tickets)

@app.route('/call_ticket', methods=['POST'])
@login_required
def call_ticket():
    operator_id = session['operator_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT number FROM tickets WHERE operator_id = ? AND status = 'called'", (operator_id,))
    current_ticket = c.fetchone()
    if current_ticket:
        conn.close()
        return jsonify({"error": "You already have a called ticket!"}), 400
    c.execute("SELECT id, number FROM tickets WHERE status = 'waiting' AND service_id IN (SELECT service_id FROM operator_services WHERE operator_id = ?) ORDER BY created_at LIMIT 1", (operator_id,))
    ticket = c.fetchone()
    if ticket:
        ticket_id, ticket_number = ticket
        c.execute("UPDATE tickets SET status = 'called', operator_id = ? WHERE id = ?", (operator_id, ticket_id))
        conn.commit()
        socketio.emit('update_queue', {'ticket': ticket_number, 'operator_id': operator_id})
        logging.info(f"Operator {operator_id} called ticket {ticket_number}")
    conn.close()
    return jsonify({"ticket": ticket_number if ticket else None})

@app.route('/finish_ticket', methods=['POST'])
@login_required
def finish_ticket():
    data = request.get_json()
    ticket = data.get('ticket')
    operator_id = session['operator_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE tickets SET status = 'finished', finished_at = ? WHERE number = ? AND operator_id = ?",
              (datetime.now().isoformat(), ticket, operator_id))
    if c.rowcount == 0:
        conn.close()
        return jsonify({"error": "Ticket not found or not yours"}), 400
    conn.commit()
    socketio.emit('remove_ticket', {'ticket': ticket})
    logging.info(f"Operator {operator_id} finished ticket {ticket}")
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/redirect_ticket', methods=['POST'])
@login_required
def redirect_ticket():
    data = request.get_json()
    ticket = data.get('ticket')
    new_operator_id = data.get('new_operator_id')
    operator_id = session['operator_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE tickets SET operator_id = ?, status = 'waiting' WHERE number = ? AND operator_id = ?",
              (new_operator_id, ticket, operator_id))
    if c.rowcount == 0:
        conn.close()
        return jsonify({"error": "Ticket not found or not yours"}), 400
    conn.commit()
    socketio.emit('remove_ticket', {'ticket': ticket})
    socketio.emit('update_queue', {'ticket': ticket, 'operator_id': new_operator_id})
    logging.info(f"Operator {operator_id} redirected ticket {ticket} to {new_operator_id}")
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    data = request.get_json()
    operator_id = session['operator_id']
    ticket_number = data.get('ticket_number')
    content = data.get('content')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO chats (ticket_number, sender_type, sender_id, content, timestamp) VALUES (?, 'operator', ?, ?, ?)",
              (ticket_number, operator_id, content, timestamp))
    conn.commit()
    socketio.emit('message', {
        'room': ticket_number,
        'sender': f"Operator {operator_id}",
        'content': content,
        'timestamp': timestamp
    })
    logging.info(f"Operator {operator_id} sent message to ticket {ticket_number}: {content}")
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/admin/upload_media', methods=['POST'])
@admin_required
def upload_media():
    if 'file' not in request.files:
        logging.error("No file uploaded")
        return jsonify({"status": "error", "message": "No file provided"}), 400
    file = request.files['file']
    if file.filename == '':
        logging.error("Empty filename")
        return jsonify({"status": "error", "message": "No file selected"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        if file_size > 100 * 1024 * 1024:  # 100MB limit
            os.remove(file_path)
            logging.error(f"File {filename} exceeds 100MB limit")
            return jsonify({"status": "error", "message": "File size exceeds 100MB limit"}), 400
        media_type = request.form.get('type')
        title = request.form.get('title')
        description = request.form.get('description')
        display_order = request.form.get('display_order', 0)
        created_at = datetime.now().isoformat()
        admin_id = session['admin_id']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO media (type, filename, title, description, display_order, created_at, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (media_type, filename, title, description, display_order, created_at, admin_id))
        conn.commit()
        conn.close()
        logging.info(f"Uploaded media: {filename}, type: {media_type}, size: {file_size} bytes")
        socketio.emit('media_updated')
        return jsonify({"status": "ok", "filename": filename})
    logging.error(f"Invalid file type: {file.filename}")
    return jsonify({"status": "error", "message": "Invalid file type"}), 400

@app.route('/admin/media', methods=['GET'])
@admin_required
def get_media():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, type, filename, title, description, display_order FROM media ORDER BY display_order, created_at")
    media = [{"id": row[0], "type": row[1], "filename": row[2], "title": row[3], "description": row[4], "display_order": row[5]} for row in c.fetchall()]
    conn.close()
    logging.info(f"Fetched {len(media)} media items")
    return jsonify(media)

@app.route('/admin/delete_media', methods=['POST'])
@admin_required
def delete_media():
    data = request.get_json()
    media_id = data.get('id')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT filename FROM media WHERE id = ?", (media_id,))
    media = c.fetchone()
    if not media:
        conn.close()
        logging.error(f"Media ID {media_id} not found")
        return jsonify({"status": "error", "message": "Media not found"}), 404
    filename = media[0]
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        logging.info(f"Removed file: {file_path}")
    c.execute("DELETE FROM media WHERE id = ?", (media_id,))
    conn.commit()
    conn.close()
    logging.info(f"Deleted media: ID {media_id}, filename {filename}")
    socketio.emit('media_updated')
    return jsonify({"status": "ok"})

@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    if room:
        join_room(room)
        logging.info(f"User joined room {room}")

@socketio.on('message')
def handle_message(data):
    room = data.get('room')
    sender = data.get('sender')
    content = data.get('content')
    sender_id = data.get('sender_id')
    timestamp = datetime.now().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO chats (ticket_number, sender_type, sender_id, content, timestamp) VALUES (?, ?, ?, ?, ?)",
              (room, sender, sender_id, content, timestamp))
    conn.commit()
    conn.close()
    emit('message', {
        'sender': sender,
        'content': content,
        'timestamp': timestamp
    }, room=room)
    logging.info(f"Message in room {room} from {sender}: {content}")

@app.route('/admin')
@admin_required
def admin():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, parent_id FROM categories")
    categories = c.fetchall()
    c.execute("SELECT s.id, s.name, c.name FROM services s JOIN categories c ON s.category_id = c.id")
    services = c.fetchall()
    c.execute("SELECT id, name, status, operator_number FROM operators")
    operators = c.fetchall()
    c.execute("SELECT operator_id, service_id FROM operator_services")
    operator_services = c.fetchall()
    c.execute("SELECT number, service_id FROM tickets WHERE status = 'waiting'")
    waiting = c.fetchall()
    c.execute("SELECT number, service_id, operator_id, created_at, finished_at FROM tickets WHERE status = 'finished'")
    stats = c.fetchall()
    c.execute("SELECT AVG(strftime('%s', finished_at) - strftime('%s', created_at)) / 60 FROM tickets WHERE finished_at IS NOT NULL")
    avg_time = round(c.fetchone()[0] or 0, 2)
    conn.close()
    return render_template('admin.html', categories=categories, services=services, operators=operators,
                           operator_services=operator_services, waiting=waiting, stats=stats, avg_time=avg_time, server_url=SERVER_URL)

@app.route('/add_category', methods=['POST'])
@admin_required
def add_category():
    name = request.form.get('name')
    parent_id = request.form.get('parent_id')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if parent_id:
        depth = get_category_depth(int(parent_id))
        if depth >= 9:
            conn.close()
            logging.warning(f"Cannot add category '{name}' under {parent_id}: maximum depth reached")
            return jsonify({"status": "error", "message": "Maximum category depth reached"}), 400
    try:
        c.execute("INSERT INTO categories (name, parent_id) VALUES (?, ?)", (name, int(parent_id) if parent_id else None))
        conn.commit()
        logging.info(f"Added category: {name} (parent_id: {parent_id or 'None'})")
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Failed to add category {name}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()
    return redirect(url_for('admin'))

@app.route('/edit_category', methods=['POST'])
@admin_required
def edit_category():
    data = request.get_json()
    category_id = data['id']
    new_name = data['name']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("UPDATE categories SET name = ? WHERE id = ?", (new_name, category_id))
        conn.commit()
        logging.info(f"Edited category {category_id}: {new_name}")
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Failed to edit category {category_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/delete_category', methods=['POST'])
@admin_required
def delete_category():
    data = request.get_json()
    category_id = data['id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM categories WHERE parent_id = ?", (category_id,))
    subcategories_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM services WHERE category_id = ?", (category_id,))
    services_count = c.fetchone()[0]
    if subcategories_count > 0 or services_count > 0:
        conn.close()
        logging.warning(f"Cannot delete category {category_id}: has subcategories or services")
        return jsonify({"status": "error", "message": "Cannot delete category with subcategories or services"}), 400
    try:
        c.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        conn.commit()
        logging.info(f"Deleted category {category_id}")
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Failed to delete category {category_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/add_service', methods=['POST'])
@admin_required
def add_service():
    name = request.form.get('name')
    category_id = request.form.get('category_id')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO services (name, category_id) VALUES (?, ?)", (name, category_id))
        conn.commit()
        logging.info(f"Added service: {name} to category {category_id}")
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Failed to add service {name}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()
    return redirect(url_for('admin'))

@app.route('/edit_service', methods=['POST'])
@admin_required
def edit_service():
    data = request.get_json()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("UPDATE services SET name = ? WHERE id = ?", (data['name'], data['id']))
        conn.commit()
        logging.info(f"Edited service {data['id']}: {data['name']}")
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Failed to edit service {data['id']}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/delete_service', methods=['POST'])
@admin_required
def delete_service():
    data = request.get_json()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("DELETE FROM services WHERE id = ?", (data['id'],))
        conn.commit()
        logging.info(f"Deleted service {data['id']}")
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Failed to delete service {data['id']}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/add_operator', methods=['POST'])
@admin_required
def add_operator():
    name = request.form.get('name')
    password = request.form.get('password')
    operator_number = request.form.get('operator_number') or None
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO operators (name, password, status, operator_number) VALUES (?, ?, 'active', ?)",
                  (name, password, operator_number))
        conn.commit()
        logging.info(f"Added operator: {name}, number: {operator_number or 'None'}")
    except sqlite3.IntegrityError:
        conn.close()
        logging.error(f"Failed to add operator {name}: duplicate operator number")
        return jsonify({"status": "error", "message": "Operator number already exists"}), 400
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Failed to add operator {name}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()
    return redirect(url_for('admin'))

@app.route('/edit_operator', methods=['POST'])
@admin_required
def edit_operator():
    data = request.get_json()
    name = data['name']
    password = data.get('password')
    status = data['status']
    operator_number = data.get('operator_number') or None
    id = data['id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        if password:
            c.execute("UPDATE operators SET name = ?, password = ?, status = ?, operator_number = ? WHERE id = ?",
                      (name, password, status, operator_number, id))
        else:
            c.execute("UPDATE operators SET name = ?, status = ?, operator_number = ? WHERE id = ?",
                      (name, status, operator_number, id))
        conn.commit()
        logging.info(f"Edited operator {id}: {name}, number: {operator_number or 'None'}")
    except sqlite3.IntegrityError:
        conn.close()
        logging.error(f"Failed to edit operator {id}: duplicate operator number")
        return jsonify({"status": "error", "message": "Operator number already exists"}), 400
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Failed to edit operator {id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/delete_operator', methods=['POST'])
@admin_required
def delete_operator():
    data = request.get_json()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        # Удалить все услуги, связанные с этим оператором
        c.execute("DELETE FROM operator_services WHERE operator_id = ?", (data['id'],))
        # Теперь удалить самого оператора
        c.execute("DELETE FROM operators WHERE id = ?", (data['id'],))
        conn.commit()
        logging.info(f"Deleted operator {data['id']} and unassigned all services")
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Failed to delete operator {data['id']}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/assign_service', methods=['POST'])
@admin_required
def assign_service():
    data = request.get_json()
    operator_id = data['operator_id']
    service_id = data['service_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM operator_services WHERE operator_id = ? AND service_id = ?", (operator_id, service_id))
    if c.fetchone():
        conn.close()
        logging.warning(f"Service {service_id} already assigned to operator {operator_id}")
        return jsonify({"status": "error", "message": "Service already assigned"}), 400
    try:
        c.execute("INSERT INTO operator_services (operator_id, service_id) VALUES (?, ?)", (operator_id, service_id))
        conn.commit()
        logging.info(f"Assigned service {service_id} to operator {operator_id}")
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Failed to assign service {service_id} to operator {operator_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/unassign_service', methods=['POST'])
@admin_required
def unassign_service():
    data = request.get_json()
    operator_id = data['operator_id']
    service_id = data['service_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("DELETE FROM operator_services WHERE operator_id = ? AND service_id = ?", (operator_id, service_id))
        conn.commit()
        logging.info(f"Unassigned service {service_id} from operator {operator_id}")
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Failed to unassign service {service_id} from operator {operator_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/display')
def display():
    return render_template('display.html', server_url=SERVER_URL)

@app.route('/tablet/<int:operator_id>')
@login_required
def tablet(operator_id):
    if session['operator_id'] != operator_id:
        abort(403)
    return render_template('tablet.html', operator_id=operator_id, server_url=SERVER_URL)

@app.route('/get_queue')
def get_queue():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT t.number, o.name, o.operator_number FROM tickets t LEFT JOIN operators o ON t.operator_id = o.id WHERE t.status = 'called'")
    tickets = [{"ticket": row[0], "operator_name": row[1], "operator_number": row[2]} for row in c.fetchall()]
    conn.close()
    logging.info(f"Fetched {len(tickets)} called tickets for queue")
    return jsonify(tickets)

@app.route('/operator/<int:operator_id>/tickets')
@login_required
def operator_tickets(operator_id):
    if session['operator_id'] != operator_id:
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT number, status FROM tickets WHERE operator_id = ? AND status IN ('waiting', 'called')", (operator_id,))
    tickets = [{"number": row[0], "status": row[1]} for row in c.fetchall()]
    conn.close()
    logging.info(f"Fetched {len(tickets)} tickets for operator {operator_id}")
    return jsonify(tickets)

if __name__ == '__main__':
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
