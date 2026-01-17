import os
import uuid
import json
import sqlite3
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Инициализация Flask с правильными путями
app = Flask(__name__, template_folder='.', static_folder='.')
app.config['SECRET_KEY'] = 'deeplink-secret-key-2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# SocketIO без async_mode - будет использовать стандартный потоковый режим
socketio = SocketIO(app, cors_allowed_origins="*")

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ========== БАЗА ДАННЫХ ==========

def get_db_connection():
    """Создание подключения к SQLite"""
    conn = sqlite3.connect('deeplink.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Инициализация базы данных при первом запуске"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Создаем таблицу пользователей, если её нет
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        avatar TEXT DEFAULT 'default.png',
        online BOOLEAN DEFAULT 0,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Создаем таблицу сообщений, если её нет
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        image_url TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        read_status BOOLEAN DEFAULT 0,
        FOREIGN KEY (sender_id) REFERENCES users (id),
        FOREIGN KEY (receiver_id) REFERENCES users (id)
    )
    ''')
    
    # Создаем тестовых пользователей, если база пустая
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        test_users = [
            ('admin', generate_password_hash('admin123')),
            ('alex', generate_password_hash('alex123')),
            ('mika', generate_password_hash('mika123')),
            ('kira', generate_password_hash('kira123')),
            ('max', generate_password_hash('max123'))
        ]
        
        for username, password in test_users:
            try:
                cursor.execute(
                    "INSERT INTO users (username, password, online) VALUES (?, ?, 1)",
                    (username, password)
                )
            except sqlite3.IntegrityError:
                pass
        
        # Добавляем тестовые сообщения
        cursor.execute("SELECT id FROM users WHERE username='admin'")
        admin_id = cursor.fetchone()[0]
        
        cursor.execute("SELECT id FROM users WHERE username='alex'")
        alex_id = cursor.fetchone()[0]
        
        test_messages = [
            (admin_id, alex_id, 'Привет! Как дела? 👋'),
            (alex_id, admin_id, 'Привет! Все отлично, а у тебя?'),
            (admin_id, alex_id, 'Тоже хорошо! Тестирую новый мессенджер 😊'),
            (alex_id, admin_id, 'Круто выглядит! Особенно дизайн!'),
        ]
        
        for sender, receiver, content in test_messages:
            cursor.execute(
                "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
                (sender, receiver, content)
            )
    
    conn.commit()
    conn.close()
    print("✅ База данных инициализирована")

# Инициализируем БД при запуске
init_database()

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validate_username(username):
    """Валидация имени пользователя"""
    username = username.strip()
    if len(username) < 4 or len(username) > 10:
        return False, "Имя должно быть от 4 до 10 символов"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Только латинские буквы, цифры и _"
    return True, username

# ========== API МАРШРУТЫ ==========

@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    """Регистрация нового пользователя"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Нет данных'}), 400
        
        username = data.get('username', '')
        password = data.get('password', '')
        
        # Валидация
        is_valid, message = validate_username(username)
        if not is_valid:
            return jsonify({'success': False, 'error': message}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Пароль должен быть минимум 6 символов'}), 400
        
        # Проверка существования пользователя
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Имя пользователя уже занято'}), 400
        
        # Создание пользователя
        hashed_password = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, password, online) VALUES (?, ?, 1)",
            (username, hashed_password)
        )
        user_id = cursor.lastrowid
        
        # Получаем данные пользователя
        cursor.execute(
            "SELECT id, username, avatar, online FROM users WHERE id = ?",
            (user_id,)
        )
        user = dict(cursor.fetchone())
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Регистрация успешна',
            'user': user
        }), 201
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Вход пользователя"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Нет данных'}), 400
        
        username = data.get('username', '')
        password = data.get('password', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Поиск пользователя
        cursor.execute(
            "SELECT id, username, password, avatar FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'Неверное имя пользователя или пароль'}), 401
        
        # Проверка пароля
        if not check_password_hash(user['password'], password):
            conn.close()
            return jsonify({'success': False, 'error': 'Неверное имя пользователя или пароль'}), 401
        
        # Обновляем статус онлайн
        cursor.execute(
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
        }), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Выход пользователя"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if user_id:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET online = 0 WHERE id = ?",
                (user_id,)
            )
            conn.commit()
            conn.close()
        
        return jsonify({'success': True, 'message': 'Выход успешен'}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    """Получение списка всех пользователей"""
    try:
        current_user_id = request.args.get('current_id', type=int)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if current_user_id:
            cursor.execute('''
                SELECT id, username, avatar, online, last_seen 
                FROM users 
                WHERE id != ? 
                ORDER BY online DESC, username ASC
            ''', (current_user_id,))
        else:
            cursor.execute('''
                SELECT id, username, avatar, online, last_seen 
                FROM users 
                ORDER BY online DESC, username ASC
            ''')
        
        users = []
        for row in cursor.fetchall():
            user = dict(row)
            # Преобразуем timestamp в читаемый формат
            if user['last_seen']:
                user['last_seen'] = datetime.fromisoformat(user['last_seen']).strftime('%H:%M')
            users.append(user)
        
        conn.close()
        return jsonify({'success': True, 'users': users}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/search', methods=['GET'])
def search_users():
    """Поиск пользователей"""
    try:
        query = request.args.get('q', '').strip()
        current_user_id = request.args.get('current_id', type=int)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if query:
            cursor.execute('''
                SELECT id, username, avatar, online 
                FROM users 
                WHERE username LIKE ? AND id != ?
                ORDER BY online DESC
                LIMIT 20
            ''', (f'%{query}%', current_user_id or 0))
        else:
            cursor.execute('''
                SELECT id, username, avatar, online 
                FROM users 
                WHERE id != ?
                ORDER BY online DESC
                LIMIT 20
            ''', (current_user_id or 0,))
        
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'users': users}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/messages', methods=['GET'])
def get_messages():
    """Получение сообщений между двумя пользователями"""
    try:
        user_id = request.args.get('user_id', type=int)
        other_id = request.args.get('other_id', type=int)
        
        if not user_id or not other_id:
            return jsonify({'success': False, 'error': 'Не указаны ID пользователей'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Получаем сообщения
        cursor.execute('''
            SELECT m.*, u.username as sender_name 
            FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE (m.sender_id = ? AND m.receiver_id = ?) 
               OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.timestamp ASC
        ''', (user_id, other_id, other_id, user_id))
        
        messages = []
        for row in cursor.fetchall():
            message = dict(row)
            # Форматируем время
            if message['timestamp']:
                dt = datetime.fromisoformat(message['timestamp'])
                message['time'] = dt.strftime('%H:%M')
                message['date'] = dt.strftime('%d.%m')
            messages.append(message)
        
        # Помечаем сообщения как прочитанные
        cursor.execute('''
            UPDATE messages 
            SET read_status = 1 
            WHERE receiver_id = ? AND sender_id = ? AND read_status = 0
        ''', (user_id, other_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'messages': messages}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Загрузка файла"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'Файл не найден'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Файл не выбран'}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_name = f"{uuid.uuid4().hex}_{filename}"
            
            # Сохраняем файл
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))
            
            return jsonify({
                'success': True,
                'url': f'/uploads/{unique_name}',
                'filename': unique_name
            }), 200
        
        return jsonify({'success': False, 'error': 'Недопустимый формат файла'}), 400
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/uploads/<filename>')
def serve_uploaded_file(filename):
    """Отдача загруженных файлов"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/health')
def health_check():
    """Проверка работоспособности сервера"""
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()}), 200

# ========== WEBSOCKET СОБЫТИЯ ==========

online_users = {}

@socketio.on('connect')
def handle_connect():
    print('🔌 Клиент подключился')

@socketio.on('disconnect')
def handle_disconnect():
    print('🔌 Клиент отключился')

@socketio.on('user_online')
def handle_user_online(data):
    """Пользователь онлайн"""
    user_id = data.get('user_id')
    if user_id:
        online_users[user_id] = request.sid
        
        # Обновляем статус в БД
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?",
            (user_id,)
        )
        conn.commit()
        conn.close()
        
        # Уведомляем всех
        emit('status_update', {
            'user_id': user_id,
            'online': True
        }, broadcast=True)

@socketio.on('user_offline')
def handle_user_offline(data):
    """Пользователь офлайн"""
    user_id = data.get('user_id')
    if user_id in online_users:
        del online_users[user_id]
        
        # Обновляем статус в БД
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET online = 0 WHERE id = ?",
            (user_id,)
        )
        conn.commit()
        conn.close()
        
        # Уведомляем всех
        emit('status_update', {
            'user_id': user_id,
            'online': False
        }, broadcast=True)

@socketio.on('send_message')
def handle_send_message(data):
    """Отправка сообщения"""
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    image_url = data.get('image_url')
    
    if not sender_id or not receiver_id or (not content and not image_url):
        return
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Сохраняем сообщение в БД
    cursor.execute('''
        INSERT INTO messages (sender_id, receiver_id, content, image_url)
        VALUES (?, ?, ?, ?)
    ''', (sender_id, receiver_id, content or '', image_url))
    
    # Получаем данные сообщения
    message_id = cursor.lastrowid
    cursor.execute('''
        SELECT m.*, u.username as sender_name 
        FROM messages m 
        JOIN users u ON m.sender_id = u.id 
        WHERE m.id = ?
    ''', (message_id,))
    
    message_data = dict(cursor.fetchone())
    
    # Форматируем время
    if message_data['timestamp']:
        dt = datetime.fromisoformat(message_data['timestamp'])
        message_data['time'] = dt.strftime('%H:%M')
    
    conn.commit()
    conn.close()
    
    # Отправляем сообщение получателю (если онлайн)
    if receiver_id in online_users:
        emit('new_message', message_data, room=online_users[receiver_id])
    
    # Отправляем обратно отправителю для подтверждения
    emit('new_message', message_data, room=request.sid)

@socketio.on('typing')
def handle_typing(data):
    """Индикатор набора текста"""
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    is_typing = data.get('is_typing')
    
    if receiver_id in online_users:
        emit('user_typing', {
            'sender_id': sender_id,
            'is_typing': is_typing
        }, room=online_users[receiver_id])

# ========== ЗАПУСК СЕРВЕРА ==========

if __name__ == '__main__':
    print("🚀 Deeplink Messenger запущен!")
    print("📌 Адрес: http://localhost:8080")
    print("👤 Тестовые пользователи: admin/admin123, alex/alex123, mika/mika123")
    
    # Запуск на стандартном потоковом режиме
    socketio.run(app, host='0.0.0.0', port=8080, debug=False)
