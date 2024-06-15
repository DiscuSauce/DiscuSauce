from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room
import uuid
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'  # Путь к файлу базы данных SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
socketio = SocketIO(app)
db = SQLAlchemy(app)

# Модель для хранения сессий
class Session(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    users = db.Column(db.PickleType)

# Создание таблицы в базе данных (если ее еще нет)
db.create_all()

# Хранилище для отслеживания активных сессий
active_sessions = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat')
def chat():
    return render_template('chat.html')

@socketio.on('connect')
def handle_connect():
    session_id = None
    for session in Session.query.all():
        if len(session.users) < 2:
            session_id = session.id
            break

    if not session_id:
        session_id = str(uuid.uuid4())
        db.session.add(Session(id=session_id, users=[]))
        db.session.commit()

    session = Session.query.get(session_id)
    session.users.append(request.sid)
    db.session.commit()

    join_room(session_id)
    emit('joined', {'session_id': session_id}, room=request.sid)

    if len(session.users) == 2:
        socketio.emit('start_chat', room=session_id)

@socketio.on('disconnect')
def handle_disconnect():
    for session in Session.query.all():
        if request.sid in session.users:
            session.users.remove(request.sid)
            db.session.commit()
            leave_room(session.id)
            if not session.users:
                db.session.delete(session)
                db.session.commit()
            else:
                emit('chat_ended', room=session.id)
            break

@socketio.on('message')
def handle_message(data):
    session_id = data['session_id']
    sender_id = request.sid
    session = Session.query.get(session_id)
    for sid in session.users:
        if sid != sender_id:
            emit('message', {'message': data['message'], 'sender': 'Anonymous'}, room=sid)
        else:
            emit('message', {'message': data['message'], 'sender': 'You'}, room=sid)

@socketio.on('end_chat')
def end_chat(data):
    session_id = data['session_id']
    emit('chat_ended', room=session_id)
    session = Session.query.get(session_id)
    for sid in session.users:
        leave_room(session_id)
    db.session.delete(session)
    db.session.commit()

if __name__ == '__main__':
    socketio.run(app)
