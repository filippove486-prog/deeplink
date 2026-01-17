import os
import uuid
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import eventlet
import sqlite3

eventlet.monkey_patch()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'deeplink-secret-key-2024-chat-app'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'mov', 'avi', 'pdf', 'doc', 'docx', 'txt'}

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'avatars'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'messages'), exist_ok=True)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('deeplink.db')
    cursor = conn.cursor()
    
    # Таблица пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            avatar TEXT DEFAULT 'default_avatar.png',
            is_online BOOLEAN DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Таблица чатов
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            is_group BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            creator_id INTEGER
        )
    ''')
    
    # Таблица участников чатов
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            room_id INTEGER NOT NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_admin BOOLEAN DEFAULT 0,
            UNIQUE(user_id, room_id)
        )
    ''')
    
    # Таблица сообщений
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            attachment TEXT,
            attachment_type TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT 0
        )
    ''')
    
    # Создаем индексы для оптимизации
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_participants_user ON chat_participants(user_id)')
    
    # Проверяем наличие пользователей
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        # Создаем тестового пользователя
        hashed_password = generate_password_hash('admin123', method='pbkdf2:sha256')
        cursor.execute('''
            INSERT INTO users (username, email, password, is_online)
            VALUES (?, ?, ?, 1)
        ''', ('admin', 'admin@deeplink.com', hashed_password))
        
        user_id = cursor.lastrowid
        
        # Создаем общий чат
        cursor.execute('''
            INSERT INTO chat_rooms (name, description, is_group, creator_id)
            VALUES (?, ?, 1, ?)
        ''', ('Общий чат', 'Добро пожаловать в DeepLink!', user_id))
        
        room_id = cursor.lastrowid
        
        # Добавляем пользователя в чат
        cursor.execute('''
            INSERT INTO chat_participants (user_id, room_id, is_admin)
            VALUES (?, ?, 1)
        ''', (user_id, room_id))
        
        # Добавляем приветственное сообщение
        cursor.execute('''
            INSERT INTO messages (room_id, sender_id, content)
            VALUES (?, ?, ?)
        ''', (room_id, user_id, '👋 Добро пожаловать в DeepLink Messenger! Начните общение прямо сейчас!'))
        
        # Создаем тестовых пользователей для демонстрации
        test_users = [
            ('user1', 'user1@deeplink.com', 'user1123'),
            ('user2', 'user2@deeplink.com', 'user2123'),
            ('user3', 'user3@deeplink.com', 'user3123')
        ]
        
        for username, email, password in test_users:
            hashed_pwd = generate_password_hash(password, method='pbkdf2:sha256')
            cursor.execute('''
                INSERT INTO users (username, email, password, is_online)
                VALUES (?, ?, ?, 0)
            ''', (username, email, hashed_pwd))
            
            test_user_id = cursor.lastrowid
            
            # Добавляем тестовых пользователей в общий чат
            cursor.execute('''
                INSERT INTO chat_participants (user_id, room_id)
                VALUES (?, ?)
            ''', (test_user_id, room_id))
            
            # Добавляем тестовые сообщения
            test_messages = [
                (room_id, test_user_id, f'Привет всем! Я {username}!'),
                (room_id, test_user_id, 'Как дела? 😊'),
                (room_id, test_user_id, 'Тестирую этот мессенджер!')
            ]
            
            for msg_room_id, msg_sender_id, msg_content in test_messages:
                cursor.execute('''
                    INSERT INTO messages (room_id, sender_id, content)
                    VALUES (?, ?, ?)
                ''', (msg_room_id, msg_sender_id, msg_content))
    
    conn.commit()
    conn.close()

# Вспомогательные функции для работы с БД
def get_db():
    conn = sqlite3.connect('deeplink.db')
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Маршруты для файлов
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Основной маршрут
@app.route('/')
def index():
    return render_template('index.html')

# API маршруты
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'Нет данных'}), 400
            
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            return jsonify({'error': 'Все поля обязательны'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Проверяем существование пользователя
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Имя пользователя уже существует'}), 400
        
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Email уже зарегистрирован'}), 400
        
        # Создаем пользователя
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        cursor.execute('''
            INSERT INTO users (username, email, password, is_online)
            VALUES (?, ?, ?, 1)
        ''', (username, email, hashed_password))
        
        user_id = cursor.lastrowid
        
        # Получаем данные пользователя
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = dict(cursor.fetchone())
        
        # Добавляем пользователя в общий чат
        cursor.execute('SELECT id FROM chat_rooms WHERE name = ?', ('Общий чат',))
        general_chat = cursor.fetchone()
        
        if general_chat:
            try:
                cursor.execute('''
                    INSERT INTO chat_participants (user_id, room_id)
                    VALUES (?, ?)
                ''', (user_id, general_chat['id']))
                
                # Добавляем приветственное сообщение от пользователя
                cursor.execute('''
                    INSERT INTO messages (room_id, sender_id, content)
                    VALUES (?, ?, ?)
                ''', (general_chat['id'], user_id, 'Привет всем! Я только что зарегистрировался! 👋'))
            except sqlite3.IntegrityError:
                pass  # Уже участник
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Регистрация успешна',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'avatar': user['avatar'],
                'is_online': bool(user['is_online'])
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Ошибка сервера: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'Нет данных'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        
        if not user_data:
            conn.close()
            return jsonify({'error': 'Неверные учетные данные'}), 401
        
        user = dict(user_data)
        
        if not check_password_hash(user['password'], password):
            conn.close()
            return jsonify({'error': 'Неверные учетные данные'}), 401
        
        # Обновляем статус пользователя
        cursor.execute('''
            UPDATE users 
            SET is_online = 1, last_seen = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (user['id'],))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Вход успешен',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'avatar': user['avatar'],
                'is_online': True
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Ошибка сервера: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'Нет данных'}), 400
            
        user_id = data.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users 
            SET is_online = 0, last_seen = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (user_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Выход успешен'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Ошибка сервера: {str(e)}'}), 500

@app.route('/api/users/search', methods=['GET'])
def search_users():
    query = request.args.get('q', '')
    current_user_id = request.args.get('current_user_id', 0)
    
    conn = get_db()
    cursor = conn.cursor()
    
    if query:
        cursor.execute('''
            SELECT id, username, avatar, is_online, last_seen 
            FROM users 
            WHERE (username LIKE ? OR email LIKE ?) 
            AND id != ?
            LIMIT 20
        ''', (f'%{query}%', f'%{query}%', current_user_id))
    else:
        # Возвращаем всех пользователей кроме текущего
        cursor.execute('''
            SELECT id, username, avatar, is_online, last_seen 
            FROM users 
            WHERE id != ?
            LIMIT 20
        ''', (current_user_id,))
    
    users = []
    for row in cursor.fetchall():
        user = dict(row)
        user['is_online'] = bool(user['is_online'])
        users.append(user)
    
    conn.close()
    return jsonify({'users': users})

@app.route('/api/chats', methods=['GET'])
def get_chats():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({'error': 'User ID required'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Получаем чаты пользователя
    cursor.execute('''
        SELECT cr.* 
        FROM chat_rooms cr
        JOIN chat_participants cp ON cr.id = cp.room_id
        WHERE cp.user_id = ?
        ORDER BY cr.created_at DESC
    ''', (user_id,))
    
    chats = []
    for room in cursor.fetchall():
        room_dict = dict(room)
        
        # Получаем последнее сообщение
        cursor.execute('''
            SELECT m.*, u.username, u.avatar 
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.room_id = ?
            ORDER BY m.timestamp DESC
            LIMIT 1
        ''', (room_dict['id'],))
        
        last_message_data = cursor.fetchone()
        last_message = dict(last_message_data) if last_message_data else None
        
        # Получаем участников (кроме текущего пользователя)
        cursor.execute('''
            SELECT u.id, u.username, u.avatar, u.is_online
            FROM users u
            JOIN chat_participants cp ON u.id = cp.user_id
            WHERE cp.room_id = ? AND u.id != ?
        ''', (room_dict['id'], user_id))
        
        other_participants = [dict(row) for row in cursor.fetchall()]
        
        # Считаем непрочитанные сообщения
        cursor.execute('''
            SELECT COUNT(*) 
            FROM messages 
            WHERE room_id = ? AND sender_id != ? AND is_read = 0
        ''', (room_dict['id'], user_id))
        
        unread_count = cursor.fetchone()[0]
        
        # Форматируем данные чата
        chat_data = {
            'id': room_dict['id'],
            'name': room_dict['name'],
            'description': room_dict['description'],
            'is_group': bool(room_dict['is_group']),
            'created_at': room_dict['created_at'],
            'last_message': last_message,
            'other_participants': other_participants,
            'unread_count': unread_count
        }
        
        chats.append(chat_data)
    
    conn.close()
    return jsonify({'chats': chats})

@app.route('/api/chats/create', methods=['POST'])
def create_chat():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'Нет данных'}), 400
            
        name = data.get('name')
        user_ids = data.get('user_ids', [])
        creator_id = data.get('creator_id')
        
        if not creator_id:
            return jsonify({'error': 'Creator ID required'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Определяем имя чата
        if not name and user_ids:
            cursor.execute('''
                SELECT username FROM users WHERE id IN ({})
            '''.format(','.join('?' * len(user_ids))), user_ids)
            
            usernames = [row[0] for row in cursor.fetchall()]
            chat_name = ', '.join(usernames[:3])
            if len(usernames) > 3:
                chat_name += f' и еще {len(usernames) - 3}'
        else:
            chat_name = name or 'Новый чат'
        
        # Создаем чат
        is_group = len(user_ids) > 1 or bool(name)
        cursor.execute('''
            INSERT INTO chat_rooms (name, is_group, creator_id)
            VALUES (?, ?, ?)
        ''', (chat_name, is_group, creator_id))
        
        room_id = cursor.lastrowid
        
        # Добавляем участников
        all_user_ids = [creator_id] + user_ids
        for uid in set(all_user_ids):
            try:
                cursor.execute('''
                    INSERT INTO chat_participants (user_id, room_id)
                    VALUES (?, ?)
                ''', (uid, room_id))
            except sqlite3.IntegrityError:
                pass  # Уже участник
        
        # Получаем данные созданного чата
        cursor.execute('SELECT * FROM chat_rooms WHERE id = ?', (room_id,))
        room = dict(cursor.fetchone())
        
        # Получаем участников для ответа
        cursor.execute('''
            SELECT u.id, u.username, u.avatar, u.is_online
            FROM users u
            JOIN chat_participants cp ON u.id = cp.user_id
            WHERE cp.room_id = ? AND u.id != ?
        ''', (room_id, creator_id))
        
        other_participants = [dict(row) for row in cursor.fetchall()]
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Чат создан',
            'room': {
                'id': room['id'],
                'name': room['name'],
                'is_group': bool(room['is_group']),
                'created_at': room['created_at'],
                'other_participants': other_participants,
                'unread_count': 0,
                'last_message': None
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Ошибка сервера: {str(e)}'}), 500

@app.route('/api/messages', methods=['GET'])
def get_messages():
    room_id = request.args.get('room_id')
    page = int(request.args.get('page', 1))
    limit = 50
    offset = (page - 1) * limit
    
    if not room_id:
        return jsonify({'error': 'Room ID required'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Получаем сообщения
    cursor.execute('''
        SELECT m.*, u.username, u.avatar 
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.room_id = ?
        ORDER BY m.timestamp DESC
        LIMIT ? OFFSET ?
    ''', (room_id, limit, offset))
    
    messages = []
    for row in cursor.fetchall():
        msg = dict(row)
        msg['sender'] = {
            'id': msg['sender_id'],
            'username': msg['username'],
            'avatar': msg['avatar']
        }
        # Форматируем время
        if msg['timestamp']:
            timestamp = datetime.fromisoformat(msg['timestamp'].replace('Z', '+00:00'))
            msg['time_formatted'] = timestamp.strftime('%H:%M')
            msg['date_formatted'] = timestamp.strftime('%d.%m.%Y')
        messages.append(msg)
    
    # Проверяем есть ли еще сообщения
    cursor.execute('''
        SELECT COUNT(*) FROM messages WHERE room_id = ?
    ''', (room_id,))
    total = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'messages': messages[::-1],  # Возвращаем в правильном порядке
        'has_next': (offset + limit) < total
    })

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Файл не найден'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Файл не выбран'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        
        # Определяем тип файла
        file_ext = filename.rsplit('.', 1)[1].lower()
        file_type = 'document'
        if file_ext in ['png', 'jpg', 'jpeg', 'gif', 'webp']:
            file_type = 'image'
        elif file_ext in ['mp4', 'mov', 'avi']:
            file_type = 'video'
        
        # Сохраняем файл
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], 'messages', unique_filename)
        file.save(save_path)
        
        return jsonify({
            'filename': unique_filename,
            'filetype': file_type,
            'url': f'/uploads/messages/{unique_filename}'
        }), 200
    
    return jsonify({'error': 'Тип файла не поддерживается'}), 400

@app.route('/api/test', methods=['GET'])
def test_api():
    """Тестовый эндпоинт для проверки работы API"""
    return jsonify({
        'status': 'ok',
        'message': 'Сервер работает!',
        'timestamp': datetime.now().isoformat()
    })

# WebSocket события
online_users = {}

@socketio.on('connect')
def handle_connect():
    print('Клиент подключился')
    emit('connected', {'message': 'Connected to DeepLink server'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Клиент отключился')

@socketio.on('user_online')
def handle_user_online(data):
    user_id = data.get('user_id')
    if user_id:
        online_users[user_id] = request.sid
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users 
            SET is_online = 1, last_seen = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (user_id,))
        conn.commit()
        conn.close()
        
        emit('user_status_changed', {
            'user_id': user_id,
            'is_online': True
        }, broadcast=True)

@socketio.on('user_offline')
def handle_user_offline(data):
    user_id = data.get('user_id')
    if user_id in online_users:
        del online_users[user_id]
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users 
            SET is_online = 0, last_seen = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (user_id,))
        conn.commit()
        conn.close()
        
        emit('user_status_changed', {
            'user_id': user_id,
            'is_online': False
        }, broadcast=True)

@socketio.on('join_room')
def handle_join_room(data):
    room_id = data.get('room_id')
    user_id = data.get('user_id')
    
    if room_id:
        join_room(str(room_id))
        
        # Помечаем сообщения как прочитанные
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE messages 
            SET is_read = 1 
            WHERE room_id = ? AND sender_id != ?
        ''', (room_id, user_id))
        conn.commit()
        conn.close()
        
        emit('room_joined', {'room_id': room_id, 'user_id': user_id}, room=str(room_id))

@socketio.on('leave_room')
def handle_leave_room(data):
    room_id = data.get('room_id')
    if room_id:
        leave_room(str(room_id))

@socketio.on('send_message')
def handle_send_message(data):
    room_id = data.get('room_id')
    sender_id = data.get('sender_id')
    content = data.get('content')
    attachment = data.get('attachment')
    attachment_type = data.get('attachment_type')
    
    if not room_id or not sender_id:
        return
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Сохраняем сообщение
    cursor.execute('''
        INSERT INTO messages (room_id, sender_id, content, attachment, attachment_type)
        VALUES (?, ?, ?, ?, ?)
    ''', (room_id, sender_id, content or '', attachment, attachment_type))
    
    message_id = cursor.lastrowid
    
    # Получаем данные сообщения
    cursor.execute('''
        SELECT m.*, u.username, u.avatar 
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.id = ?
    ''', (message_id,))
    
    message_data = dict(cursor.fetchone())
    
    # Форматируем данные
    message_data['sender'] = {
        'id': sender_id,
        'username': message_data['username'],
        'avatar': message_data['avatar']
    }
    
    if message_data['timestamp']:
        timestamp = datetime.fromisoformat(message_data['timestamp'].replace('Z', '+00:00'))
        message_data['time_formatted'] = timestamp.strftime('%H:%M')
    
    conn.commit()
    conn.close()
    
    # Отправляем сообщение всем в комнате
    emit('new_message', message_data, room=str(room_id))

@socketio.on('typing')
def handle_typing(data):
    room_id = data.get('room_id')
    user_id = data.get('user_id')
    is_typing = data.get('is_typing')
    
    if room_id:
        emit('user_typing', {
            'user_id': user_id,
            'is_typing': is_typing
        }, room=str(room_id), include_self=False)

# Инициализируем базу данных при запуске
with app.app_context():
    init_db()
    print("База данных инициализирована!")
    print("Тестовые пользователи созданы:")
    print("- admin / admin123")
    print("- user1 / user1123")
    print("- user2 / user2123")
    print("- user3 / user3123")

if __name__ == '__main__':
    print("DeepLink Messenger запускается на http://0.0.0.0:8080")
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)
