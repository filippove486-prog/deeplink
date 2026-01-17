import os
import uuid
import json
import sqlite3
import re
import base64
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__, template_folder='.', static_folder='.')
app.config['SECRET_KEY'] = 'deeplink-secret-key-2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ========== БАЗА ДАННЫХ ==========

def get_db():
    conn = sqlite3.connect('deeplink.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Пользователи с аватаркой в base64
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        avatar TEXT DEFAULT '',
        online BOOLEAN DEFAULT 0,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Сообщения
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room TEXT NOT NULL,
        sender_id INTEGER NOT NULL,
        sender_name TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id)
    )''')
    
    # Проверяем наличие пользователей
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        # Создаем тестовых пользователей
        from werkzeug.security import generate_password_hash
        users = [
            ('admin', 'admin123', ''),
            ('alex', 'alex123', ''),
            ('mika', 'mika123', ''),
            ('kira', 'kira123', ''),
            ('max', 'max123', '')
        ]
        
        for username, password, avatar in users:
            try:
                c.execute(
                    "INSERT INTO users (username, password, avatar, online) VALUES (?, ?, ?, 1)",
                    (username, generate_password_hash(password), avatar)
                )
            except:
                pass
        
        conn.commit()
        print("✅ Тестовые пользователи созданы")
    
    conn.close()

# ========== API МАРШРУТЫ ==========

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    try:
        from werkzeug.security import generate_password_hash
        
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Заполните все поля'})
        
        if len(username) < 4 or len(username) > 10:
            return jsonify({'success': False, 'error': 'Имя должно быть 4-10 символов'})
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return jsonify({'success': False, 'error': 'Только латинские буквы, цифры и _'})
        
        conn = get_db()
        c = conn.cursor()
        
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Имя уже занято'})
        
        hashed_pw = generate_password_hash(password)
        c.execute(
            "INSERT INTO users (username, password, online) VALUES (?, ?, 1)",
            (username, hashed_pw)
        )
        user_id = c.lastrowid
        
        c.execute(
            "SELECT id, username, avatar, online FROM users WHERE id = ?",
            (user_id,)
        )
        user = dict(c.fetchone())
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Регистрация успешна',
            'user': user
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/login', methods=['POST'])
def login():
    try:
        from werkzeug.security import check_password_hash
        
        data = request.get_json()
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
        
        c.execute(
            "UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?",
            (user['id'],)
        )
        
        user_data = {
            'id': user['id'],
            'username': user['username'],
            'avatar': user['avatar'],
            'online': True
        }
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Вход успешен',
            'user': user_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if user_id:
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE users SET online = 0 WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()
        
        return jsonify({'success': True})
    except:
        return jsonify({'success': False})

@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        current_id = request.args.get('current_id', type=int)
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT id, username, avatar, online, last_seen 
            FROM users 
            WHERE id != ? 
            ORDER BY online DESC, username ASC
        ''', (current_id or 0,))
        
        users = [dict(row) for row in c.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'users': users})
    except:
        return jsonify({'success': False, 'users': []})

@app.route('/api/messages', methods=['GET'])
def get_messages():
    try:
        room = request.args.get('room', 'general')
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT m.*, u.avatar as sender_avatar 
            FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE m.room = ? 
            ORDER BY m.timestamp ASC
            LIMIT 100
        ''', (room,))
        
        messages = []
        for row in c.fetchall():
            msg = dict(row)
            if msg['timestamp']:
                dt = datetime.fromisoformat(msg['timestamp'])
                msg['time'] = dt.strftime('%H:%M')
            messages.append(msg)
        
        conn.close()
        return jsonify({'success': True, 'messages': messages})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        new_username = data.get('username', '').strip()
        avatar_data = data.get('avatar', '')
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Требуется ID пользователя'})
        
        if not new_username:
            return jsonify({'success': False, 'error': 'Имя пользователя не может быть пустым'})
        
        if len(new_username) < 4 or len(new_username) > 10:
            return jsonify({'success': False, 'error': 'Имя должно быть 4-10 символов'})
        
        if not re.match(r'^[a-zA-Z0-9_]+$', new_username):
            return jsonify({'success': False, 'error': 'Только латинские буквы, цифры и _'})
        
        conn = get_db()
        c = conn.cursor()
        
        # Проверяем, свободно ли новое имя
        c.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new_username, user_id))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Имя уже занято'})
        
        # Обновляем имя пользователя
        c.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
        
        # Обновляем имя в старых сообщениях
        c.execute("UPDATE messages SET sender_name = ? WHERE sender_id = ?", (new_username, user_id))
        
        # Сохраняем аватар если есть
        if avatar_data and avatar_data.startswith('data:image'):
            c.execute("UPDATE users SET avatar = ? WHERE id = ?", (avatar_data, user_id))
        
        # Получаем обновленные данные
        c.execute(
            "SELECT id, username, avatar, online FROM users WHERE id = ?",
            (user_id,)
        )
        user = dict(c.fetchone())
        
        conn.commit()
        conn.close()
        
        # Отправляем всем обновление через WebSocket
        socketio.emit('user_updated', {
            'user_id': user_id,
            'new_username': new_username,
            'avatar': avatar_data if avatar_data else user['avatar']
        }, broadcast=True)
        
        return jsonify({
            'success': True,
            'message': 'Профиль обновлен',
            'user': user
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ========== WEBSOCKET СОБЫТИЯ ==========

@socketio.on('connect')
def handle_connect():
    print('🔌 Новое подключение')

@socketio.on('disconnect')
def handle_disconnect():
    print('🔌 Отключение')

@socketio.on('user_online')
def handle_user_online(data):
    user_id = data.get('user_id')
    if user_id:
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        # Отправляем всем обновление статуса
        socketio.emit('user_status', {
            'user_id': user_id,
            'online': True
        }, broadcast=True)

@socketio.on('user_offline')
def handle_user_offline(data):
    user_id = data.get('user_id')
    if user_id:
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE users SET online = 0 WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        socketio.emit('user_status', {
            'user_id': user_id,
            'online': False
        }, broadcast=True)

@socketio.on('join_room')
def handle_join_room(data):
    room = data.get('room', 'general')
    join_room(room)

@socketio.on('send_message')
def handle_send_message(data):
    try:
        sender_id = data.get('sender_id')
        sender_name = data.get('sender_name')
        content = data.get('content', '').strip()
        room = data.get('room', 'general')
        
        if not content or not sender_id:
            return
        
        conn = get_db()
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO messages (room, sender_id, sender_name, content)
            VALUES (?, ?, ?, ?)
        ''', (room, sender_id, sender_name, content))
        
        message_id = c.lastrowid
        
        c.execute('''
            SELECT m.*, u.avatar as sender_avatar 
            FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE m.id = ?
        ''', (message_id,))
        
        message_data = dict(c.fetchone())
        
        if message_data['timestamp']:
            dt = datetime.fromisoformat(message_data['timestamp'])
            message_data['time'] = dt.strftime('%H:%M')
        
        conn.commit()
        conn.close()
        
        # ВАЖНО: Отправляем сообщение всем в комнате
        socketio.emit('new_message', message_data, room=room, broadcast=True)
        
    except Exception as e:
        print(f"Ошибка отправки сообщения: {e}")

@socketio.on('typing')
def handle_typing(data):
    room = data.get('room', 'general')
    sender_id = data.get('sender_id')
    is_typing = data.get('is_typing', False)
    
    # Отправляем всем в комнате кроме отправителя
    emit('user_typing', {
        'sender_id': sender_id,
        'is_typing': is_typing
    }, room=room, include_self=False)

# ========== ЗАПУСК ==========

if __name__ == '__main__':
    init_db()
    print("🚀 Deeplink запущен на порту 10000")
    socketio.run(app, host='0.0.0.0', port=10000, debug=False, allow_unsafe_werkzeug=True)
