import os
import base64
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder='.', static_folder='.')
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///deeplink.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Используем threading mode для SocketIO (без eventlet)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
db = SQLAlchemy(app)

# Модели БД
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    avatar = db.Column(db.Text, default='default')
    status = db.Column(db.String(20), default='offline')
    theme = db.Column(db.String(20), default='dark')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    chat_type = db.Column(db.String(20), default='private')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)

# Создаем таблицы
with app.app_context():
    db.create_all()

# Маршруты
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Заполните все поля'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Имя уже занято'}), 400
        
        user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Регистрация успешна',
            'user_id': user.id
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'success': False, 'error': 'Неверный логин или пароль'}), 401
        
        user.status = 'online'
        db.session.commit()
        
        session['user_id'] = user.id
        
        return jsonify({
            'success': True,
            'message': 'Вход выполнен',
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar,
                'theme': user.theme,
                'status': user.status
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.status = 'offline'
            db.session.commit()
    session.clear()
    return jsonify({'success': True, 'message': 'Выход выполнен'})

@app.route('/api/user/me')
def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Не авторизован'}), 401
    
    user = User.query.get(user_id)
    return jsonify({
        'id': user.id,
        'username': user.username,
        'avatar': user.avatar,
        'theme': user.theme,
        'status': user.status
    })

@app.route('/api/user/update', methods=['POST'])
def update_user():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'Не авторизован'}), 401
    
    try:
        data = request.json
        user = User.query.get(user_id)
        
        if 'username' in data:
            new_username = data['username'].strip()
            if new_username != user.username:
                existing = User.query.filter_by(username=new_username).first()
                if existing:
                    return jsonify({'success': False, 'error': 'Имя уже занято'}), 400
                user.username = new_username
        
        if 'theme' in data:
            user.theme = data['theme']
        
        if 'avatar' in data and data['avatar']:
            user.avatar = data['avatar']
        
        db.session.commit()
        
        # Уведомляем всех о смене ника
        socketio.emit('user_updated', {
            'user_id': user.id,
            'username': user.username,
            'avatar': user.avatar
        }, broadcast=True)
        
        return jsonify({'success': True, 'message': 'Профиль обновлен'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/search')
def search_users():
    query = request.args.get('q', '').strip()
    user_id = session.get('user_id')
    
    if not user_id or len(query) < 2:
        return jsonify([])
    
    users = User.query.filter(
        User.username.ilike(f'%{query}%'),
        User.id != user_id
    ).limit(10).all()
    
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'avatar': u.avatar,
        'status': u.status
    } for u in users])

@app.route('/api/chats')
def get_chats():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Не авторизован'}), 401
    
    # Находим все чаты пользователя
    member_chats = ChatMember.query.filter_by(user_id=user_id).all()
    chat_ids = [mc.chat_id for mc in member_chats]
    
    chats = []
    for chat_id in chat_ids:
        chat = Chat.query.get(chat_id)
        if not chat:
            continue
        
        # Получаем последнее сообщение
        last_message = Message.query.filter_by(chat_id=chat_id)\
            .order_by(Message.created_at.desc()).first()
        
        # Получаем участников чата для имени
        members = ChatMember.query.filter_by(chat_id=chat_id).all()
        if chat.chat_type == 'private' and len(members) == 2:
            other_member_id = next((m.user_id for m in members if m.user_id != user_id), None)
            if other_member_id:
                other_user = User.query.get(other_member_id)
                chat_name = other_user.username if other_user else 'Пользователь'
            else:
                chat_name = 'Приватный чат'
        else:
            chat_name = chat.name or 'Групповой чат'
        
        chats.append({
            'id': chat.id,
            'name': chat_name,
            'type': chat.chat_type,
            'last_message': {
                'content': last_message.content if last_message else '',
                'time': last_message.created_at.isoformat() if last_message else ''
            },
            'unread_count': 0
        })
    
    return jsonify(chats)

@app.route('/api/chat/<int:chat_id>/messages')
def get_chat_messages(chat_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Не авторизован'}), 401
    
    # Проверяем доступ к чату
    membership = ChatMember.query.filter_by(chat_id=chat_id, user_id=user_id).first()
    if not membership:
        return jsonify({'error': 'Нет доступа'}), 403
    
    messages = Message.query.filter_by(chat_id=chat_id, is_deleted=False)\
        .order_by(Message.created_at.asc()).all()
    
    result = []
    for msg in messages:
        user = User.query.get(msg.user_id)
        result.append({
            'id': msg.id,
            'user_id': msg.user_id,
            'username': user.username if user else 'Неизвестно',
            'avatar': user.avatar if user else 'default',
            'content': msg.content,
            'type': msg.message_type,
            'created_at': msg.created_at.isoformat(),
            'is_self': msg.user_id == user_id
        })
    
    return jsonify(result)

@app.route('/api/chat/create', methods=['POST'])
def create_chat():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'Не авторизован'}), 401
    
    try:
        data = request.json
        chat_type = data.get('type', 'private')
        member_ids = data.get('members', [])
        
        if user_id not in member_ids:
            member_ids.append(user_id)
        
        # Для приватного чата проверяем существование
        if chat_type == 'private' and len(member_ids) == 2:
            # Ищем существующий приватный чат между этими пользователями
            existing = db.session.query(ChatMember.chat_id)\
                .filter(ChatMember.user_id.in_(member_ids))\
                .group_by(ChatMember.chat_id)\
                .having(db.func.count(ChatMember.user_id) == 2)\
                .first()
            
            if existing:
                return jsonify({'success': True, 'chat_id': existing[0]})
        
        # Создаем новый чат
        chat = Chat(
            name=data.get('name', ''),
            chat_type=chat_type
        )
        db.session.add(chat)
        db.session.flush()
        
        # Добавляем участников
        for member_id in member_ids:
            member = ChatMember(chat_id=chat.id, user_id=member_id)
            db.session.add(member)
        
        db.session.commit()
        
        return jsonify({'success': True, 'chat_id': chat.id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/message/delete', methods=['POST'])
def delete_message():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'Не авторизован'}), 401
    
    try:
        data = request.json
        message_id = data.get('message_id')
        
        message = Message.query.get(message_id)
        if not message or message.user_id != user_id:
            return jsonify({'success': False, 'error': 'Нет прав'}), 403
        
        message.is_deleted = True
        db.session.commit()
        
        # Уведомляем об удалении
        socketio.emit('message_deleted', {
            'message_id': message_id,
            'chat_id': message.chat_id
        }, broadcast=True)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# SocketIO события
@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')
        user = User.query.get(user_id)
        if user:
            user.status = 'online'
            db.session.commit()
            
            emit('user_status', {
                'user_id': user_id,
                'status': 'online'
            }, broadcast=True, include_self=False)

@socketio.on('disconnect')
def handle_disconnect():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.status = 'offline'
            db.session.commit()
            
            emit('user_status', {
                'user_id': user_id,
                'status': 'offline'
            }, broadcast=True, include_self=False)

@socketio.on('join_chat')
def handle_join_chat(data):
    chat_id = data.get('chat_id')
    user_id = session.get('user_id')
    
    if user_id and chat_id:
        join_room(f'chat_{chat_id}')
        join_room(f'user_{user_id}')

@socketio.on('send_message')
def handle_send_message(data):
    user_id = session.get('user_id')
    if not user_id:
        return
    
    chat_id = data.get('chat_id')
    content = data.get('content', '').strip()
    message_type = data.get('type', 'text')
    
    if not content or not chat_id:
        return
    
    # Проверяем доступ к чату
    membership = ChatMember.query.filter_by(chat_id=chat_id, user_id=user_id).first()
    if not membership:
        return
    
    # Сохраняем сообщение
    message = Message(
        chat_id=chat_id,
        user_id=user_id,
        content=content,
        message_type=message_type
    )
    db.session.add(message)
    db.session.commit()
    
    # Получаем данные пользователя
    user = User.query.get(user_id)
    
    # Подготавливаем данные для отправки
    message_data = {
        'id': message.id,
        'chat_id': chat_id,
        'user_id': user_id,
        'username': user.username,
        'avatar': user.avatar,
        'content': content,
        'type': message_type,
        'created_at': message.created_at.isoformat(),
        'is_self': False  # Для других пользователей
    }
    
    # Отправляем всем в чате, кроме отправителя
    emit('new_message', message_data, room=f'chat_{chat_id}', broadcast=True, include_self=False)
    
    # Отправляем отправителю с флагом is_self=True
    message_data['is_self'] = True
    emit('new_message', message_data, room=f'user_{user_id}')

@socketio.on('typing')
def handle_typing(data):
    chat_id = data.get('chat_id')
    user_id = session.get('user_id')
    
    if user_id and chat_id:
        user = User.query.get(user_id)
        emit('user_typing', {
            'user_id': user_id,
            'username': user.username,
            'chat_id': chat_id
        }, room=f'chat_{chat_id}', broadcast=True, include_self=False)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=True, allow_unsafe_werkzeug=True)

