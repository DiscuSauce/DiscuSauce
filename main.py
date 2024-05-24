import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin
import html
import psycopg2

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci')

# PostgreSQL configuration
POSTGRES_USER = os.getenv('POSTGRES_USER', 'default')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', '80qhdfubDyWs')
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'ep-lucky-breeze-a22r9wts-pooler.eu-central-1.aws.neon.tech')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'verceldb')
POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')

def get_db_connection():
    if 'db' not in g:
        g.db = psycopg2.connect(
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST,
            database=POSTGRES_DB,
            port=POSTGRES_PORT
        )
    return g.db

def init_db():
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL,
            content TEXT NOT NULL,
            upvotes INT DEFAULT 0,
            downvotes INT DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY,
            post_id INT NOT NULL,
            user_id INT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS votes (
            id SERIAL PRIMARY KEY,
            post_id INT NOT NULL,
            user_id INT NOT NULL,
            vote INT NOT NULL,
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    db.commit()
    cursor.close()

@app.before_request
def before_request():
    g.db = get_db_connection()
    init_db()

@app.teardown_request
def teardown_request(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def sanitize_input(input):
    return html.escape(input)

def get_user_id(username):
    cursor = get_db_connection().cursor()
    cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()
    cursor.close()
    return user[0] if user else None

def get_user(user_id):
    cursor = get_db_connection().cursor()
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return {'id': user[0], 'username': user[1], 'password': user[2]} if user else None

def create_user(username, password):
    db = get_db_connection()
    cursor = db.cursor()
    hashed_password = generate_password_hash(password)
    cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
    db.commit()
    cursor.execute('SELECT lastval()')
    user_id = cursor.fetchone()[0]
    cursor.close()
    return user_id

def create_post(user_id, content):
    cursor = g.db.cursor()
    cursor.execute("INSERT INTO posts (user_id, content) VALUES (%s, %s)", (user_id, content))
    g.db.commit()
    cursor.execute('SELECT lastval()')
    post_id = cursor.fetchone()[0]
    cursor.close()
    return post_id

def flash_message(category, message):
    flash(message, category)

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/')
def index():
    if 'username' in session:
        db = get_db_connection()
        with db.cursor() as cursor:
            cursor.execute('SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY (upvotes - downvotes) DESC')
            posts = cursor.fetchall()
            cursor.execute('SELECT post_id, vote FROM votes WHERE user_id = %s', (session['user_id'],))
            user_votes = {vote['post_id']: vote['vote'] for vote in cursor.fetchall()}
        db.close()
        return render_template('index.html', username=session['username'], posts=posts, user_votes=user_votes)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_id = get_user_id(username)
        if user_id:
            user = get_user(user_id)
            if user and check_password_hash(user['password'], password):
                session['username'] = username
                session['user_id'] = user_id
                if username == 'admin':
                    session['admin'] = True
                return redirect(url_for('index'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if len(username) < 3:
            flash_message('error', 'Username must be at least 3 characters long')
        elif len(password) < 8:
            flash_message('error', 'Password must be at least 8 characters long')
        else:
            if get_user_id(username):
                flash_message('error', 'Username already exists')
            else:
                user_id = create_user(username, password)
                session['username'] = username
                session['user_id'] = user_id
                if username == 'admin':
                    session['admin'] = True
                return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor()
    if request.method == 'POST':
        new_username = request.form['new_username']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_username and len(new_username) < 3:
            flash_message('error', 'Username must be at least 3 characters long')
        elif new_username:
            if get_user_id(new_username):
                flash_message('error', 'Username already exists')
            else:
                cursor.execute('UPDATE users SET username = %s WHERE id = %s', (new_username, user_id))
                session['username'] = new_username
                flash_message('success', 'Username updated successfully')
        if new_password:
            if len(new_password) < 8:
                flash_message('error', 'Password must be at least 8 characters long')
            elif new_password != confirm_password:
                flash_message('error', 'Passwords do not match')
            else:
                hashed_password = generate_password_hash(new_password)
                cursor.execute('UPDATE users SET password = %s WHERE id = %s', (hashed_password, user_id))
                flash_message('success', 'Password updated successfully')
        db.commit()
    cursor.execute('SELECT username FROM users WHERE id = %s', (user_id,))
    username = cursor.fetchone()[0]
    cursor.close()
    return render_template('profile.html', username=username)

@app.route('/create', methods=['GET', 'POST'])
def create():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form['content']
        content = sanitize_input(content)
        create_post(session['user_id'], content)
        return redirect(url_for('index'))
    return render_template('create.html')

@app.route('/upvote/<int:post_id>', methods=['POST'])
def upvote(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    cursor = g.db.cursor()
    cursor.execute('SELECT * FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user_id))
    vote = cursor.fetchone()
    if vote:
        if vote[3] == 1:
            cursor.execute('DELETE FROM votes WHERE id = %s', (vote[0],))
            cursor.execute('UPDATE posts SET upvotes = upvotes - 1 WHERE id = %s', (post_id,))
        else:
            cursor.execute('UPDATE votes SET vote = 1 WHERE id = %s', (vote[0],))
            cursor.execute('UPDATE posts SET upvotes = upvotes + 1, downvotes = downvotes - 1 WHERE id = %s', (post_id,))
    else:
        cursor.execute('INSERT INTO votes (post_id, user_id, vote) VALUES (%s, %s, %s)', (post_id, user_id, 1))
        cursor.execute('UPDATE posts SET upvotes = upvotes + 1 WHERE id = %s', (post_id,))
    g.db.commit()
    cursor.close()
    return redirect(url_for('index'))

@app.route('/downvote/<int:post_id>', methods=['POST'])
def downvote(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    cursor = g.db.cursor()
    cursor.execute('SELECT * FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user_id))
    vote = cursor.fetchone()
    if vote:
        if vote[3] == -1:
            cursor.execute('DELETE FROM votes WHERE id = %s', (vote[0],))
            cursor.execute('UPDATE posts SET downvotes = downvotes - 1 WHERE id = %s', (post_id,))
        else:
            cursor.execute('UPDATE votes SET vote = -1 WHERE id = %s', (vote[0],))
            cursor.execute('UPDATE posts SET upvotes = upvotes - 1, downvotes = downvotes + 1 WHERE id = %s', (post_id,))
    else:
        cursor.execute('INSERT INTO votes (post_id, user_id, vote) VALUES (%s, %s, %s)', (post_id, user_id, -1))
        cursor.execute('UPDATE posts SET downvotes = downvotes + 1 WHERE id = %s', (post_id,))
    g.db.commit()
    cursor.close()
    return redirect(url_for('index'))

@app.route('/delete/<int:post_id>', methods=['POST'])
def delete(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    cursor = g.db.cursor()
    cursor.execute('DELETE FROM comments WHERE post_id = %s', (post_id,))
    cursor.execute('DELETE FROM votes WHERE post_id = %s', (post_id,))
    cursor.execute('DELETE FROM posts WHERE id = %s', (post_id,))
    g.db.commit()
    cursor.close()
    return redirect(url_for('index'))

@app.route('/comment/<int:post_id>', methods=['POST'])
def comment(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    content = request.form['content']
    content = sanitize_input(content)
    cursor = g.db.cursor()
    cursor.execute('INSERT INTO comments (post_id, user_id, content) VALUES (%s, %s, %s)', (post_id, session['user_id'], content))
    g.db.commit()
    cursor.close()
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
