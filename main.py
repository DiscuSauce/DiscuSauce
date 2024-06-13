from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

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
    for sid, users in active_sessions.items():
        if len(users) < 2:
            session_id = sid
            break

    if not session_id:
        session_id = str(uuid.uuid4())
        active_sessions[session_id] = []

    active_sessions[session_id].append(request.sid)
    join_room(session_id)
    emit('joined', {'session_id': session_id}, room=request.sid)

    if len(active_sessions[session_id]) == 2:
        socketio.emit('start_chat', room=session_id)

@socketio.on('disconnect')
def handle_disconnect():
    for session_id, users in list(active_sessions.items()):
        if request.sid in users:
            users.remove(request.sid)
            leave_room(session_id)
            if not users:
                del active_sessions[session_id]
            else:
                # Оповещение оставшегося пользователя о завершении чата
                emit('chat_ended', room=session_id)
            break

@socketio.on('message')
def handle_message(data):
    session_id = data['session_id']
    sender_id = request.sid
    for sid in active_sessions[session_id]:
        if sid != sender_id:
            emit('message', {'message': data['message'], 'sender': 'Anonymous'}, room=sid)
        else:
            emit('message', {'message': data['message'], 'sender': 'You'}, room=sid)

@socketio.on('end_chat')
def end_chat(data):
    session_id = data['session_id']
    emit('chat_ended', room=session_id)
    for sid in active_sessions[session_id]:
        leave_room(session_id)
    del active_sessions[session_id]

if __name__ == '__main__':
    socketio.run(app)
