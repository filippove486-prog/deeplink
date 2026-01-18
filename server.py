import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import base64
import hashlib
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///deeplink.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Модели базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    avatar = db.Column(db.Text, default='default_avatar.png')
    status = db.Column(db.String(20), default='offline')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    theme = db.Column(db.String(20), default='dark')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    chat_type = db.Column(db.String(20), default='private')  # private, group
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
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
    message_type = db.Column(db.String(20), default='text')  # text, image, file
    media_url = db.Column(db.Text)
    is_deleted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reply_to = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    contact_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='pending')  # pending, accepted, blocked
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Создаем таблицы
with app.app_context():
    db.create_all()

# Роуты
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password)
    )
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully', 'user_id': user.id})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    user.status = 'online'
    db.session.commit()
    
    session['user_id'] = user.id
    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'username': user.username,
            'avatar': user.avatar,
            'theme': user.theme
        }
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.status = 'offline'
            db.session.commit()
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/user/me')
def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(user_id)
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'avatar': user.avatar,
        'theme': user.theme,
        'status': user.status
    })

@app.route('/api/user/update', methods=['PUT'])
def update_user():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    user = User.query.get(user_id)
    
    if 'username' in data:
        existing = User.query.filter_by(username=data['username']).first()
        if existing and existing.id != user_id:
            return jsonify({'error': 'Username already taken'}), 400
        user.username = data['username']
    
    if 'theme' in data:
        user.theme = data['theme']
    
    if 'avatar' in data:
        user.avatar = data['avatar']
    
    db.session.commit()
    
    # Оповещаем всех о смене ника
    socketio.emit('user_updated', {
        'user_id': user.id,
        'username': user.username,
        'avatar': user.avatar
    }, broadcast=True)
    
    return jsonify({'message': 'Profile updated'})

@app.route('/api/users/search')
def search_users():
    query = request.args.get('q', '')
    if not query:
        return jsonify([])
    
    users = User.query.filter(
        User.username.ilike(f'%{query}%')
    ).limit(20).all()
    
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
        return jsonify({'error': 'Not authenticated'}), 401
    
    chats = Chat.query.join(ChatMember).filter(
        ChatMember.user_id == user_id
    ).all()
    
    result = []
    for chat in chats:
        last_message = Message.query.filter_by(chat_id=chat.id)\
            .order_by(Message.created_at.desc()).first()
        
        result.append({
            'id': chat.id,
            'name': chat.name,
            'type': chat.chat_type,
            'last_message': {
                'content': last_message.content if last_message else '',
                'time': last_message.created_at.isoformat() if last_message else ''
            } if last_message else None
        })
    
    return jsonify(result)

@app.route('/api/chat/<int:chat_id>/messages')
def get_chat_messages(chat_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Проверяем, что пользователь состоит в чате
    membership = ChatMember.query.filter_by(
        chat_id=chat_id, user_id=user_id
    ).first()
    if not membership:
        return jsonify({'error': 'Access denied'}), 403
    
    messages = Message.query.filter_by(chat_id=chat_id)\
        .order_by(Message.created_at.asc()).all()
    
    return jsonify([{
        'id': m.id,
        'user_id': m.user_id,
        'content': m.content,
        'type': m.message_type,
        'media_url': m.media_url,
        'created_at': m.created_at.isoformat(),
        'is_deleted': m.is_deleted,
        'reply_to': m.reply_to
    } for m in messages])

@app.route('/api/chat/create', methods=['POST'])
def create_chat():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    chat_type = data.get('type', 'private')
    member_ids = data.get('members', [])
    
    if user_id not in member_ids:
        member_ids.append(user_id)
    
    # Для приватного чата проверяем существование
    if chat_type == 'private' and len(member_ids) == 2:
        existing = Chat.query.join(ChatMember).filter(
            Chat.chat_type == 'private',
            ChatMember.user_id.in_(member_ids)
        ).group_by(Chat.id).having(db.func.count(ChatMember.user_id) == 2).first()
        
        if existing:
            return jsonify({'chat_id': existing.id})
    
    chat = Chat(
        name=data.get('name', 'New Chat'),
        chat_type=chat_type,
        created_by=user_id
    )
    db.session.add(chat)
    db.session.flush()
    
    # Добавляем участников
    for member_id in member_ids:
        member = ChatMember(chat_id=chat.id, user_id=member_id)
        db.session.add(member)
    
    db.session.commit()
    
    return jsonify({'chat_id': chat.id})

# Socket.IO события
@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.status = 'online'
            db.session.commit()
            emit('user_status', {
                'user_id': user.id,
                'status': 'online'
            }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.status = 'offline'
            user.last_seen = datetime.utcnow()
            db.session.commit()
            emit('user_status', {
                'user_id': user.id,
                'status': 'offline',
                'last_seen': user.last_seen.isoformat()
            }, broadcast=True)

@socketio.on('join_chat')
def handle_join_chat(data):
    chat_id = data.get('chat_id')
    join_room(f'chat_{chat_id}')

@socketio.on('send_message')
def handle_send_message(data):
    user_id = session.get('user_id')
    if not user_id:
        return
    
    chat_id = data['chat_id']
    content = data['content']
    message_type = data.get('type', 'text')
    media_url = data.get('media_url')
    reply_to = data.get('reply_to')
    
    # Проверяем доступ к чату
    membership = ChatMember.query.filter_by(
        chat_id=chat_id, user_id=user_id
    ).first()
    if not membership:
        return
    
    message = Message(
        chat_id=chat_id,
        user_id=user_id,
        content=content,
        message_type=message_type,
        media_url=media_url,
        reply_to=reply_to
    )
    db.session.add(message)
    db.session.commit()
    
    user = User.query.get(user_id)
    
    message_data = {
        'id': message.id,
        'chat_id': chat_id,
        'user_id': user_id,
        'username': user.username,
        'avatar': user.avatar,
        'content': content,
        'type': message_type,
        'media_url': media_url,
        'created_at': message.created_at.isoformat(),
        'reply_to': reply_to
    }
    
    # Отправляем всем в чате
    emit('new_message', message_data, room=f'chat_{chat_id}', broadcast=True)
    # И глобально для обновления списка чатов
    emit('message_sent', {
        'chat_id': chat_id,
        'last_message': content[:50],
        'time': message.created_at.isoformat()
    }, broadcast=True)

@socketio.on('delete_message')
def handle_delete_message(data):
    user_id = session.get('user_id')
    if not user_id:
        return
    
    message_id = data['message_id']
    message = Message.query.get(message_id)
    
    if message and message.user_id == user_id:
        message.is_deleted = True
        db.session.commit()
        
        emit('message_deleted', {
            'message_id': message_id,
            'chat_id': message.chat_id
        }, room=f'chat_{message.chat_id}', broadcast=True)

@socketio.on('typing')
def handle_typing(data):
    chat_id = data['chat_id']
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        emit('user_typing', {
            'user_id': user_id,
            'username': user.username,
            'chat_id': chat_id
        }, room=f'chat_{chat_id}', broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, allow_unsafe_werkzeug=True)
