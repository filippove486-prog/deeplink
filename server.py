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

app = Flask(__name__, template_folder='.', static_folder='.')
app.config['SECRET_KEY'] = 'deeplink-mega-secret-2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
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
    
    # Пользователи
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        password TEXT NOT NULL,
        avatar TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        theme TEXT DEFAULT 'dark',
        online BOOLEAN DEFAULT 0,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Чаты (личные и групповые)
    c.execute('''CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        is_group BOOLEAN DEFAULT 0,
        avatar TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Участники чатов
    c.execute('''CREATE TABLE IF NOT EXISTS chat_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(chat_id, user_id),
        FOREIGN KEY (chat_id) REFERENCES chats(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Сообщения
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        sender_name TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        read_by TEXT DEFAULT '[]',
        FOREIGN KEY (chat_id) REFERENCES chats(id),
        FOREIGN KEY (sender_id) REFERENCES users(id)
    )''')
    
    # Тестовые пользователи
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        from werkzeug.security import generate_password_hash
        
        test_users = [
            ('admin', 'admin@deeplink.com', generate_password_hash('admin123'), '👑 Администратор'),
            ('alex', 'alex@deeplink.com', generate_password_hash('alex123'), 'Привет! Я Алекс'),
            ('mika', 'mika@deeplink.com', generate_password_hash('mika123'), 'Люблю путешествовать'),
            ('kira', 'kira@deeplink.com', generate_password_hash('kira123'), 'Дизайнер из Москвы'),
            ('max', 'max@deeplink.com', generate_password_hash('max123'), 'Разработчик Deeplink'),
            ('anna', 'anna@deeplink.com', generate_password_hash('anna123'), 'Фотограф'),
            ('dima', 'dima@deeplink.com', generate_password_hash('dima123'), 'Студент МГУ'),
            ('olga', 'olga@deeplink.com', generate_password_hash('olga123'), 'Маркетолог'),
            ('serg', 'serg@deeplink.com', generate_password_hash('serg123'), 'Предприниматель'),
            ('lena', 'lena@deeplink.com', generate_password_hash('lena123'), 'Блогер')
        ]
        
        for username, email, password, bio in test_users:
            try:
                c.execute(
                    """INSERT INTO users (username, email, password, bio, online) 
                    VALUES (?, ?, ?, ?, 1)""",
                    (username, email, password, bio)
                )
            except:
                pass
        
        conn.commit()
        print(f"✅ Создано {len(test_users)} тестовых пользователей")
    
    conn.close()

init_db()

# ========== ПОЛЬЗОВАТЕЛИ ==========

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not username or not email or not password:
            return jsonify({'success': False, 'error': 'Заполните все поля'})
        
        if len(username) < 4 or len(username) > 20:
            return jsonify({'success': False, 'error': 'Имя: 4-20 символов'})
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return jsonify({'success': False, 'error': 'Только латинские буквы, цифры и _'})
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Пароль: минимум 6 символов'})
        
        conn = get_db()
        c = conn.cursor()
        
        # Проверка имени
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Имя уже занято'})
        
        # Проверка email
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Email уже используется'})
        
        hashed_pw = generate_password_hash(password)
        c.execute(
            """INSERT INTO users (username, email, password, online, bio) 
            VALUES (?, ?, ?, 1, ?)""",
            (username, email, hashed_pw, f'Новый пользователь Deeplink')
        )
        user_id = c.lastrowid
        
        c.execute(
            "SELECT id, username, email, avatar, bio, theme, online FROM users WHERE id = ?",
            (user_id,)
        )
        user = dict(c.fetchone())
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'user': user,
            'message': 'Регистрация успешна'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, username))
        user = c.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'Неверные данные'})
        
        if not check_password_hash(user['password'], password):
            conn.close()
            return jsonify({'success': False, 'error': 'Неверные данные'})
        
        c.execute("UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],))
        
        user_data = {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'avatar': user['avatar'],
            'bio': user['bio'],
            'theme': user['theme'],
            'online': True
        }
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'user': user_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/users/search', methods=['GET'])
def search_users():
    try:
        query = request.args.get('q', '').strip()
        current_id = request.args.get('current_id', type=int)
        
        conn = get_db()
        c = conn.cursor()
        
        if query:
            c.execute('''
                SELECT id, username, avatar, bio, online 
                FROM users 
                WHERE (username LIKE ? OR email LIKE ?) 
                AND id != ?
                ORDER BY 
                    CASE WHEN username LIKE ? THEN 1 ELSE 2 END,
                    online DESC,
                    username ASC
                LIMIT 50
            ''', (f'%{query}%', f'%{query}%', current_id or 0, f'{query}%'))
        else:
            c.execute('''
                SELECT id, username, avatar, bio, online 
                FROM users 
                WHERE id != ?
                ORDER BY online DESC, username ASC
                LIMIT 50
            ''', (current_id or 0,))
        
        users = [dict(row) for row in c.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'users': users})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        bio = data.get('bio', '').strip()
        avatar = data.get('avatar', '')
        theme = data.get('theme', 'dark')
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Требуется ID'})
        
        if username and (len(username) < 4 or len(username) > 20):
            return jsonify({'success': False, 'error': 'Имя: 4-20 символов'})
        
        conn = get_db()
        c = conn.cursor()
        
        # Проверка имени
        if username:
            c.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, user_id))
            if c.fetchone():
                conn.close()
                return jsonify({'success': False, 'error': 'Имя уже занято'})
        
        # Проверка email
        if email:
            c.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, user_id))
            if c.fetchone():
                conn.close()
                return jsonify({'success': False, 'error': 'Email уже используется'})
        
        # Обновляем данные
        updates = []
        params = []
        
        if username:
            updates.append("username = ?")
            params.append(username)
            
            # Обновляем имя в сообщениях
            c.execute("UPDATE messages SET sender_name = ? WHERE sender_id = ?", (username, user_id))
        
        if email:
            updates.append("email = ?")
            params.append(email)
        
        if bio:
            updates.append("bio = ?")
            params.append(bio)
        
        if avatar:
            updates.append("avatar = ?")
            params.append(avatar)
        
        if theme:
            updates.append("theme = ?")
            params.append(theme)
        
        if updates:
            params.append(user_id)
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            c.execute(query, params)
        
        # Получаем обновленные данные
        c.execute(
            "SELECT id, username, email, avatar, bio, theme, online FROM users WHERE id = ?",
            (user_id,)
        )
        user = dict(c.fetchone())
        
        conn.commit()
        conn.close()
        
        # Отправляем обновление через WebSocket
        socketio.emit('profile_updated', {
            'user_id': user_id,
            'username': username or user['username'],
            'avatar': avatar or user['avatar'],
            'theme': theme
        }, broadcast=True)
        
        return jsonify({
            'success': True,
            'user': user,
            'message': 'Профиль обновлен'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ========== ЧАТЫ И СООБЩЕНИЯ ==========

@app.route('/api/chats', methods=['GET'])
def get_chats():
    try:
        user_id = request.args.get('user_id', type=int)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Требуется ID пользователя'})
        
        conn = get_db()
        c = conn.cursor()
        
        # Получаем чаты пользователя
        c.execute('''
            SELECT c.*, cm.joined_at 
            FROM chats c
            JOIN chat_members cm ON c.id = cm.chat_id
            WHERE cm.user_id = ?
            ORDER BY c.created_at DESC
        ''', (user_id,))
        
        chats = []
        for row in c.fetchall():
            chat = dict(row)
            
            # Получаем участников (для личных чатов - собеседника)
            c.execute('''
                SELECT u.id, u.username, u.avatar, u.online 
                FROM users u
                JOIN chat_members cm ON u.id = cm.user_id
                WHERE cm.chat_id = ? AND u.id != ?
            ''', (chat['id'], user_id))
            
            members = [dict(member) for member in c.fetchall()]
            
            # Для личного чата используем имя собеседника
            if not chat['is_group'] and members:
                chat['display_name'] = members[0]['username']
                chat['display_avatar'] = members[0]['avatar']
            else:
                chat['display_name'] = chat['name']
                chat['display_avatar'] = chat['avatar']
            
            # Получаем последнее сообщение
            c.execute('''
                SELECT * FROM messages 
                WHERE chat_id = ? 
                ORDER BY timestamp DESC 
                LIMIT 1
            ''', (chat['id'],))
            
            last_msg = c.fetchone()
            chat['last_message'] = dict(last_msg) if last_msg else None
            
            # Считаем непрочитанные
            c.execute('''
                SELECT COUNT(*) FROM messages 
                WHERE chat_id = ? 
                AND NOT json_contains(read_by, ?)
                AND sender_id != ?
            ''', (chat['id'], json.dumps(user_id), user_id))
            
            chat['unread_count'] = c.fetchone()[0]
            
            chats.append(chat)
        
        conn.close()
        return jsonify({'success': True, 'chats': chats})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/chat/create', methods=['POST'])
def create_chat():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        other_id = data.get('other_id')
        
        if not user_id or not other_id:
            return jsonify({'success': False, 'error': 'Требуются ID пользователей'})
        
        if user_id == other_id:
            return jsonify({'success': False, 'error': 'Нельзя создать чат с самим собой'})
        
        conn = get_db()
        c = conn.cursor()
        
        # Проверяем существующий личный чат
        c.execute('''
            SELECT c.id 
            FROM chats c
            JOIN chat_members cm1 ON c.id = cm1.chat_id
            JOIN chat_members cm2 ON c.id = cm2.chat_id
            WHERE cm1.user_id = ? AND cm2.user_id = ? 
            AND NOT c.is_group
        ''', (user_id, other_id))
        
        existing_chat = c.fetchone()
        
        if existing_chat:
            # Возвращаем существующий чат
            chat_id = existing_chat['id']
        else:
            # Создаем новый чат
            c.execute("SELECT username FROM users WHERE id = ?", (other_id,))
            other_user = c.fetchone()
            chat_name = f"{other_user['username']}" if other_user else "Личный чат"
            
            c.execute(
                "INSERT INTO chats (name, is_group) VALUES (?, 0)",
                (chat_name,)
            )
            chat_id = c.lastrowid
            
            # Добавляем участников
            c.execute(
                "INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?), (?, ?)",
                (chat_id, user_id, chat_id, other_id)
            )
        
        conn.commit()
        
        # Получаем данные чата
        c.execute('''
            SELECT c.* FROM chats c WHERE c.id = ?
        ''', (chat_id,))
        
        chat = dict(c.fetchone())
        
        # Получаем собеседника
        c.execute('''
            SELECT u.id, u.username, u.avatar, u.online 
            FROM users u
            JOIN chat_members cm ON u.id = cm.user_id
            WHERE cm.chat_id = ? AND u.id != ?
        ''', (chat_id, user_id))
        
        other_user = c.fetchone()
        chat['other_user'] = dict(other_user) if other_user else None
        
        conn.close()
        
        return jsonify({
            'success': True,
            'chat': chat,
            'message': 'Чат создан'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/messages', methods=['GET'])
def get_messages():
    try:
        chat_id = request.args.get('chat_id', type=int)
        user_id = request.args.get('user_id', type=int)
        
        if not chat_id or not user_id:
            return jsonify({'success': False, 'error': 'Требуется ID чата и пользователя'})
        
        conn = get_db()
        c = conn.cursor()
        
        # Получаем сообщения
        c.execute('''
            SELECT m.*, u.avatar as sender_avatar 
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.chat_id = ?
            ORDER BY m.timestamp ASC
            LIMIT 100
        ''', (chat_id,))
        
        messages = []
        for row in c.fetchall():
            msg = dict(row)
            if msg['timestamp']:
                dt = datetime.fromisoformat(msg['timestamp'].replace('Z', '+00:00'))
                msg['time'] = dt.strftime('%H:%M')
                msg['date'] = dt.strftime('%d.%m.%Y')
            messages.append(msg)
        
        # Помечаем как прочитанные
        c.execute('''
            UPDATE messages 
            SET read_by = json_set(
                COALESCE(read_by, '[]'),
                '$[#]',
                ?
            )
            WHERE chat_id = ? 
            AND NOT json_contains(COALESCE(read_by, '[]'), ?)
            AND sender_id != ?
        ''', (json.dumps(user_id), chat_id, json.dumps(user_id), user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'messages': messages})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ========== WEBSOCKET ==========

online_users = {}

@socketio.on('connect')
def handle_connect():
    print(f'🔌 Новое подключение: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    # Удаляем отключившегося пользователя
    for user_id, data in list(online_users.items()):
        if data['sid'] == request.sid:
            del online_users[user_id]
            
            # Обновляем статус в БД
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE users SET online = 0 WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()
            
            # Уведомляем всех
            emit('user_offline', {'user_id': user_id}, broadcast=True)
            print(f'👤 Пользователь {user_id} офлайн')
            break

@socketio.on('join')
def handle_join(data):
    user_id = data.get('user_id')
    if user_id:
        online_users[user_id] = {
            'sid': request.sid,
            'joined_at': datetime.now().isoformat()
        }
        
        # Обновляем статус в БД
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        emit('user_online', {'user_id': user_id}, broadcast=True)
        print(f'👤 Пользователь {user_id} онлайн')

@socketio.on('join_chat')
def handle_join_chat(data):
    chat_id = data.get('chat_id')
    user_id = data.get('user_id')
    
    if chat_id and user_id:
        join_room(str(chat_id))
        
        # Отмечаем сообщения как прочитанные
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            UPDATE messages 
            SET read_by = json_set(
                COALESCE(read_by, '[]'),
                '$[#]',
                ?
            )
            WHERE chat_id = ? 
            AND NOT json_contains(COALESCE(read_by, '[]'), ?)
            AND sender_id != ?
        ''', (json.dumps(user_id), chat_id, json.dumps(user_id), user_id))
        conn.commit()
        conn.close()

@socketio.on('send_message')
def handle_send_message(data):
    try:
        chat_id = data.get('chat_id')
        sender_id = data.get('sender_id')
        sender_name = data.get('sender_name')
        content = data.get('content', '').strip()
        
        if not content or not chat_id or not sender_id:
            return
        
        # Сохраняем в БД
        conn = get_db()
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO messages (chat_id, sender_id, sender_name, content)
            VALUES (?, ?, ?, ?)
        ''', (chat_id, sender_id, sender_name, content))
        
        message_id = c.lastrowid
        
        # Получаем сохраненное сообщение
        c.execute('''
            SELECT m.*, u.avatar as sender_avatar 
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.id = ?
        ''', (message_id,))
        
        message = dict(c.fetchone())
        
        if message['timestamp']:
            dt = datetime.fromisoformat(message['timestamp'].replace('Z', '+00:00'))
            message['time'] = dt.strftime('%H:%M')
        
        # Получаем участников чата
        c.execute('''
            SELECT user_id FROM chat_members WHERE chat_id = ?
        ''', (chat_id,))
        
        members = [row['user_id'] for row in c.fetchall()]
        
        conn.commit()
        conn.close()
        
        # Отправляем сообщение всем участникам чата
        for member_id in members:
            if member_id != sender_id and member_id in online_users:
                emit('new_message', message, room=online_users[member_id]['sid'])
        
        # Отправляем обратно отправителю
        emit('new_message', message, room=request.sid)
        
        # Отправляем в комнату чата
        emit('new_message', message, room=str(chat_id), broadcast=True)
        
        print(f'📨 Сообщение в чат {chat_id}: {content[:50]}...')
        
    except Exception as e:
        print(f'Ошибка отправки сообщения: {e}')

@socketio.on('typing')
def handle_typing(data):
    chat_id = data.get('chat_id')
    user_id = data.get('user_id')
    is_typing = data.get('is_typing')
    
    if chat_id and user_id:
        emit('user_typing', {
            'chat_id': chat_id,
            'user_id': user_id,
            'is_typing': is_typing
        }, room=str(chat_id), include_self=False)

# ========== ЗАПУСК ==========

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'users_online': len(online_users)})

if __name__ == '__main__':
    print("🚀 Deeplink Mega запущен на порту 10000")
    print("👥 10 тестовых пользователей созданы")
    print("🔍 Поиск пользователей работает")
    print("🎨 Темы: dark/light/gray")
    
    socketio.run(app, 
                 host='0.0.0.0', 
                 port=10000, 
                 debug=False, 
                 allow_unsafe_werkzeug=True)
