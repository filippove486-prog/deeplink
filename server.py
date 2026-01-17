import os
import uuid
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'deeplink-ultra-secret-2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
socketio = SocketIO(app, cors_allowed_origins="*")

# Подключение к БД
def get_db():
    conn = sqlite3.connect('deeplink.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Инициализация БД
def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Пользователи
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        avatar TEXT DEFAULT 'default.png',
        online INTEGER DEFAULT 0,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Сообщения
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        image TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        read INTEGER DEFAULT 0,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
    )''')
    
    # Создаем тестовых пользователей
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        users = [
            ('admin', generate_password_hash('admin123')),
            ('alice', generate_password_hash('alice123')),
            ('bob', generate_password_hash('bob123')),
            ('max', generate_password_hash('max123')),
            ('luna', generate_password_hash('luna123'))
        ]
        c.executemany("INSERT INTO users (username, password, online) VALUES (?, ?, 1)", users)
        
        # Тестовые сообщения
        test_messages = [
            (2, 1, 'Привет админ! 👋'),
            (1, 2, 'Привет Алиса! Как дела?'),
            (2, 1, 'Отлично! Тестирую этот крутой мессенджер 😎'),
            (3, 1, 'Йоу админ!'),
            (4, 1, 'Хей! Как работает Deeplink?'),
            (5, 1, 'Красивый дизайн! 💫')
        ]
        c.executemany("INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)", test_messages)
    
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Валидация
    if not username or not password:
        return jsonify({'success': False, 'error': 'Заполните все поля'})
    
    if len(username) < 4 or len(username) > 10:
        return jsonify({'success': False, 'error': 'Имя: 4-10 символов'})
    
    if not re.match('^[a-zA-Z0-9_]+$', username):
        return jsonify({'success': False, 'error': 'Только буквы, цифры и _'})
    
    conn = get_db()
    c = conn.cursor()
    
    # Проверка существования
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({'success': False, 'error': 'Имя занято'})
    
    # Создание пользователя
    hashed_pw = generate_password_hash(password)
    c.execute("INSERT INTO users (username, password, online) VALUES (?, ?, 1)", 
              (username, hashed_pw))
    user_id = c.lastrowid
    
    conn.commit()
    
    # Получаем данные пользователя
    c.execute("SELECT id, username, avatar, online FROM users WHERE id = ?", (user_id,))
    user = dict(c.fetchone())
    conn.close()
    
    return jsonify({
        'success': True,
        'user': user
    })

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'success': False, 'error': 'Неверные данные'})
    
    if not check_password_hash(user['password'], password):
        conn.close()
        return jsonify({'success': False, 'error': 'Неверные данные'})
    
    # Обновляем статус
    c.execute("UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?", 
              (user['id'],))
    conn.commit()
    
    user_data = {
        'id': user['id'],
        'username': user['username'],
        'avatar': user['avatar'],
        'online': True
    }
    
    conn.close()
    return jsonify({'success': True, 'user': user_data})

@app.route('/api/logout', methods=['POST'])
def logout():
    data = request.json
    user_id = data.get('user_id')
    
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET online = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/users', methods=['GET'])
def get_users():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, avatar, online, last_seen FROM users ORDER BY online DESC, username")
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({'users': users})

@app.route('/api/users/search', methods=['GET'])
def search_users():
    query = request.args.get('q', '')
    current_id = request.args.get('current_id', type=int)
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, avatar, online FROM users WHERE username LIKE ? AND id != ? LIMIT 10", 
              (f'%{query}%', current_id))
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({'users': users})

@app.route('/api/messages/<int:user_id>/<int:other_id>', methods=['GET'])
def get_messages(user_id, other_id):
    conn = get_db()
    c = conn.cursor()
    
    # Получаем сообщения между пользователями
    c.execute('''SELECT m.*, u.username as sender_name 
                FROM messages m 
                JOIN users u ON m.sender_id = u.id 
                WHERE (sender_id = ? AND receiver_id = ?) 
                OR (sender_id = ? AND receiver_id = ?) 
                ORDER BY timestamp''', 
              (user_id, other_id, other_id, user_id))
    
    messages = []
    for row in c.fetchall():
        msg = dict(row)
        # Форматируем время
        dt = datetime.fromisoformat(msg['timestamp'])
        msg['time'] = dt.strftime('%H:%M')
        msg['date'] = dt.strftime('%d.%m')
        messages.append(msg)
    
    # Помечаем как прочитанные
    c.execute("UPDATE messages SET read = 1 WHERE receiver_id = ? AND sender_id = ?", 
              (user_id, other_id))
    conn.commit()
    conn.close()
    
    return jsonify({'messages': messages})

@app.route('/api/upload', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'Нет файла'})
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Файл не выбран'})
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4()}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))
        
        return jsonify({
            'success': True,
            'url': f'/uploads/{unique_name}',
            'filename': unique_name
        })
    
    return jsonify({'success': False, 'error': 'Неверный формат'})

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# WebSocket события
online_users = {}

@socketio.on('connect')
def handle_connect():
    print('Новое подключение')

@socketio.on('user_online')
def handle_online(data):
    user_id = data.get('user_id')
    if user_id:
        online_users[user_id] = request.sid
        emit('status_update', {'user_id': user_id, 'online': True}, broadcast=True)

@socketio.on('user_offline')
def handle_offline(data):
    user_id = data.get('user_id')
    if user_id in online_users:
        del online_users[user_id]
        emit('status_update', {'user_id': user_id, 'online': False}, broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    image = data.get('image')
    
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender_id, receiver_id, message, image) VALUES (?, ?, ?, ?)",
              (sender_id, receiver_id, message, image))
    msg_id = c.lastrowid
    
    c.execute("SELECT m.*, u.username as sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = ?", (msg_id,))
    msg_data = dict(c.fetchone())
    
    # Форматируем время
    dt = datetime.fromisoformat(msg_data['timestamp'])
    msg_data['time'] = dt.strftime('%H:%M')
    msg_data['date'] = dt.strftime('%d.%m')
    
    conn.commit()
    conn.close()
    
    # Отправляем получателю если онлайн
    if receiver_id in online_users:
        emit('new_message', msg_data, room=online_users[receiver_id])
    
    # Отправляем отправителю для подтверждения
    emit('new_message', msg_data, room=request.sid)

@socketio.on('typing')
def handle_typing(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    is_typing = data.get('is_typing')
    
    if receiver_id in online_users:
        emit('user_typing', {
            'sender_id': sender_id,
            'is_typing': is_typing
        }, room=online_users[receiver_id])

# Инициализация при запуске
init_db()
print("✅ Deeplink запущен!")
print("📱 Тестовые пользователи: admin/admin123, alice/alice123, bob/bob123")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)
