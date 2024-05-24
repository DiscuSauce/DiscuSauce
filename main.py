import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin
import html

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci')
DATABASE = 'app.db'

def get_db_connection():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db_connection()
    with app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))
    db.commit()

@app.before_first_request
def initialize():
    init_db()

@app.teardown_appcontext
def teardown_db(exception):
    close_db_connection(exception)

def sanitize_input(input):
    return html.escape(input)

def get_user_id(username):
    cursor = get_db_connection().cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    cursor.close()
    return user['id'] if user else None

def get_user(user_id):
    cursor = get_db_connection().cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return {'id': user['id'], 'username': user['username'], 'password': user['password']} if user else None

def create_user(username, password):
    db = get_db_connection()
    cursor = db.cursor()
    hashed_password = generate_password_hash(password)
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    db.commit()
    user_id = cursor.lastrowid
    cursor.close()
    return user_id

def create_post(user_id, content):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("INSERT INTO posts (user_id, content) VALUES (?, ?)", (user_id, content))
    db.commit()
    post_id = cursor.lastrowid
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
        cursor = db.cursor()
        cursor.execute('SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY (upvotes - downvotes) DESC')
        posts = cursor.fetchall()
        cursor.execute('SELECT post_id, vote FROM votes WHERE user_id = ?', (session['user_id'],))
        user_votes = {vote['post_id']: vote['vote'] for vote in cursor.fetchall()}
        cursor.close()
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
                cursor.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, user_id))
                session['username'] = new_username
                flash_message('success', 'Username updated successfully')
        if new_password:
            if len(new_password) < 8:
                flash_message('error', 'Password must be at least 8 characters long')
            elif new_password != confirm_password:
                flash_message('error', 'Passwords do not match')
            else:
                hashed_password = generate_password_hash(new_password)
                cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))
                flash_message('success', 'Password updated successfully')
        db.commit()
    cursor.execute('SELECT * FROM posts WHERE user_id = ?', (user_id,))
    user_posts = cursor.fetchall()
    cursor.close()
    db.close()
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
            user_id = session['user_id']
            create_post(user_id, content)
            flash_message('success', 'Post created successfully')
            return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM posts WHERE id = ? AND user_id = ?', (post_id, user_id))
    post = cursor.fetchone()
    if post:
        cursor.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
        cursor.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        db.commit()
        flash_message('success', 'Post deleted successfully')
    else:
        flash_message('error', 'You are not authorized to delete this post')
    cursor.close()
    db.close()
    return redirect(url_for('profile'))

@app.route('/vote/<int:post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute('SELECT vote FROM votes WHERE post_id = ? AND user_id = ?', (post_id, user_id))
    existing_vote = cursor.fetchone()
    if existing_vote:
        if existing_vote['vote'] == vote:
            cursor.execute('DELETE FROM votes WHERE post_id = ? AND user_id = ?', (post_id, user_id))
            if vote == 1:
                cursor.execute('UPDATE posts SET upvotes = upvotes - 1 WHERE id = ?', (post_id,))
            else:
                cursor.execute('UPDATE posts SET downvotes = downvotes - 1 WHERE id = ?', (post_id,))
        else:
            cursor.execute('UPDATE votes SET vote = ? WHERE post_id = ? AND user_id = ?', (vote, post_id, user_id))
            if vote == 1:
                cursor.execute('UPDATE posts SET upvotes = upvotes + 1, downvotes = downvotes - 1 WHERE id = ?', (post_id,))
            else:
                cursor.execute('UPDATE posts SET upvotes = upvotes - 1, downvotes = downvotes + 1 WHERE id = ?', (post_id,))
    else:
        cursor.execute('INSERT INTO votes (post_id, user_id, vote) VALUES (?, ?, ?)', (post_id, user_id, vote))
        if vote == 1:
            cursor.execute('UPDATE posts SET upvotes = upvotes + 1 WHERE id = ?', (post_id,))
        else:
            cursor.execute('UPDATE posts SET downvotes = downvotes + 1 WHERE id = ?', (post_id,))
    db.commit()
    cursor.close()
    db.close()
    return redirect(url_for('index'))

@app.route('/delete_comment/<int:comment_id>')
def delete_comment(comment_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM comments WHERE id = ? AND user_id = ?', (comment_id, user_id))
    comment = cursor.fetchone()
    if comment:
        cursor.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
        db.commit()
        flash_message('success', 'Comment deleted successfully')
    else:
        flash_message('error', 'You are not authorized to delete this comment')
    cursor.close()
    db.close()
    return redirect(url_for('profile'))

@app.route('/comment/<int:post_id>', methods=['POST'])
def comment(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    content = sanitize_input(request.form['content'])
    if len(content) > 500:
        flash_message('error', 'Comment content exceeds 500 characters limit')
    else:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)', (post_id, user_id, content))
        db.commit()
        cursor.close()
        db.close()
        flash_message('success', 'Comment added successfully')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
