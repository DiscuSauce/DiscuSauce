import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin
import html
import psycopg2

app = Flask(__name__)
app.secret_key = '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci'

# PostgreSQL configuration
POSTGRES_USER = os.getenv('POSTGRES_USER', 'szirpaekvdajlu')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', '2919c09af5c341f7fdf44343be41fb562a22a77e68fb6b28c3310f38acafc8f0')
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'ec2-52-23-12-61.compute-1.amazonaws.com')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'd6sb633vs4llrl')
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
    return user

def create_user(username, password):
    db = get_db_connection()
    cursor = db.cursor()
    hashed_password = generate_password_hash(password)
    cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
    db.commit()
    user_id = cursor.lastrowid
    cursor.close()
    return user_id

def create_post(user_id, content):
    cursor = g.db.cursor()
    cursor.execute("INSERT INTO posts (user_id, content) VALUES (%s, %s)", (user_id, content))
    post_id = cursor.lastrowid
    g.db.commit()
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
        # Get the database connection
        db = get_db_connection()
        # Create a cursor within the connection context
        with db.cursor() as cursor:
            # Execute the SQL queries using the cursor
            cursor.execute('SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY (upvotes - downvotes) DESC')
            posts = cursor.fetchall()
            cursor.execute('SELECT post_id, vote FROM votes WHERE user_id = %s', (session['user_id'],))
            user_votes = {vote['post_id']: vote['vote'] for vote in cursor.fetchall()}
        # Don't forget to close the database connection
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
                old_username = session['username']
                g.cursor.execute('UPDATE users SET username = %s WHERE id = %s', (new_username, user_id))
                session['username'] = new_username
                flash_message('success', 'Username updated successfully')
        if new_password:
            if len(new_password) < 8:
                flash_message('error', 'Password must be at least 8 characters long')
            elif new_password != confirm_password:
                flash_message('error', 'Passwords do not match')
            else:
                hashed_password = generate_password_hash(new_password)
                g.cursor.execute('UPDATE users SET password = %s WHERE id = %s', (hashed_password, user_id))
                flash_message('success', 'Password updated successfully')
        g.db.commit()
    g.cursor.execute('SELECT * FROM posts WHERE user_id = %s', (user_id,))
    user_posts = g.cursor.fetchall()
    return render_template('profile.html', posts=user_posts)

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form['content']
        if len(content.split()) > 64:
            flash_message('error', 'Post content exceeds 64 words limit')
        else:
            user_id = session['user_id']  # Получаем user_id из сессии пользователя
            create_post_in_db(user_id, content)
            flash_message('success', 'Post created successfully')
            return redirect(url_for('index'))
    return render_template('create_post.html')

def create_post_in_db(user_id, content):
    db = get_db_connection()
    cursor = db.cursor()
    
    # Проверяем, существует ли user_id в таблице "users"
    cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
    user_exists = cursor.fetchone()
    
    if user_exists:
        # Если пользователь существует, выполняем вставку поста
        cursor.execute("INSERT INTO posts (user_id, content) VALUES (%s, %s)", (user_id, content))
        db.commit()
        flash_message('success', 'Post created successfully')
    else:
        flash_message('error', 'User does not exist')
    
    cursor.close()
    db.close()

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    g.cursor.execute('SELECT * FROM posts WHERE id = %s AND user_id = %s', (post_id, user_id))
    post = g.cursor.fetchone()
    if post:
        # Удаляем все комментарии, связанные с этим постом
        g.cursor.execute('DELETE FROM comments WHERE post_id = %s', (post_id,))
        # Теперь удаляем сам пост
        g.cursor.execute('DELETE FROM posts WHERE id = %s', (post_id,))
        g.db.commit()
        flash_message('success', 'Post deleted successfully')
    else:
        flash_message('error', 'You are not authorized to delete this post')
    return redirect(url_for('profile'))

@app.route('/vote/<int:post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    g.cursor.execute('SELECT vote FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user_id))
    existing_vote = g.cursor.fetchone()
    if existing_vote:
        if existing_vote['vote'] == vote:
            g.cursor.execute('DELETE FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user_id))
            if vote == 1:
                g.cursor.execute('UPDATE posts SET upvotes = upvotes - 1 WHERE id = %s', (post_id,))
            else:
                g.cursor.execute('UPDATE posts SET downvotes = downvotes - 1 WHERE id = %s', (post_id,))
        else:
            g.cursor.execute('UPDATE votes SET vote = %s WHERE post_id = %s AND user_id = %s', (vote, post_id, user_id))
            if vote == 1:
                g.cursor.execute('UPDATE posts SET upvotes = upvotes + 1, downvotes = downvotes - 1 WHERE id = %s', (post_id,))
            else:
                g.cursor.execute('UPDATE posts SET upvotes = upvotes - 1, downvotes = downvotes + 1 WHERE id = %s', (post_id,))
    else:
        g.cursor.execute('INSERT INTO votes (post_id, user_id, vote) VALUES (%s, %s, %s)', (post_id, user_id, vote))
        if vote == 1:
            g.cursor.execute('UPDATE posts SET upvotes = upvotes + 1 WHERE id = %s', (post_id,))
        else:
            g.cursor.execute('UPDATE posts SET downvotes = downvotes + 1 WHERE id = %s', (post_id,))
    g.db.commit()
    return redirect(url_for('index'))

@app.route('/view_post/<int:post_id>')
def view_post(post_id):
    g.cursor.execute('SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id WHERE posts.id = %s', (post_id,))
    post = g.cursor.fetchone()
    if not post:
        return 'Post not found', 404

    g.cursor.execute('SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE post_id = %s', (post_id,))
    comments = g.cursor.fetchall()
    if not comments:
        comments = []  # Пустой список, если нет комментариев

    return render_template('view_post.html', post=post, comments=comments)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('admin', None)
    return redirect(url_for('login'))

@app.route('/create_comment/<int:post_id>', methods=['POST'])
def create_comment(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    content = sanitize_input(request.form['comment'])
    user_id = session['user_id']
    g.db.execute('INSERT INTO comments (post_id, user_id, content) VALUES (%s, %s, %s)', (post_id, user_id, content))
    g.db.commit()
    flash('Comment added successfully', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/admin')
def admin():
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    g.cursor.execute('SELECT id, username FROM users')
    users = g.cursor.fetchall()
    g.cursor.execute('SELECT id, content FROM posts')
    posts = g.cursor.fetchall()
    return render_template('admin.html', users=users, posts=posts)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    g.cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    g.db.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin_delete_post/<int:post_id>')
def admin_delete_post(post_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    g.cursor.execute('DELETE FROM posts WHERE id = %s', (post_id,))
    g.db.commit()
    flash('Post deleted successfully', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
