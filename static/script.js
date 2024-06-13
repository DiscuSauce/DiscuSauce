document.addEventListener('DOMContentLoaded', () => {
    const socket = io();

    const form = document.getElementById('form');
    const input = document.getElementById('input');
    const messages = document.getElementById('messages');
    let session_id = null;

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        if (input.value) {
            socket.emit('message', { message: input.value, session_id: session_id });
            input.value = '';
        }
    });

    socket.on('joined', (data) => {
        session_id = data.session_id;
    });

    socket.on('start_chat', () => {
        console.log('Chat started');
    });

    socket.on('message', (data) => {
        addMessage(data);
    });

    function addMessage(data) {
        const item = document.createElement('li');
        item.classList.add('message', 'list-group-item');
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        item.innerHTML = `
            <p class="sender">${data.sender} <span class="time">${time}</span></p>
            <p class="text">${data.message}</p>
        `;
        if (data.sender === 'You') {
            item.classList.add('my-message', 'bg-success', 'text-white');
        } else {
            item.classList.add('other-message', 'bg-light');
        }
        messages.appendChild(item);
        messages.scrollTop = messages.scrollHeight;
    }

    document.getElementById('end-chat').addEventListener('click', () => {
        if (confirm('Вы уверены, что хотите завершить чат?')) {
            socket.emit('end_chat', { session_id: session_id });
        }
    });

    socket.on('chat_ended', () => {
        alert('Чат завершен.');
        window.location.href = '/';
    });

    socket.on('disconnect', () => {
        alert('Соединение потеряно.');
        window.location.href = '/';
    });
});
