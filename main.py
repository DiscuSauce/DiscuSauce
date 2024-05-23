import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin
import html
import mysql.connector

app = Flask(__name__)
app.secret_key = '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci'

# MySQL configuration
MYSQL_USER = os.getenv('MYSQL_USER', 'jck8kpiny0fmzh0u')
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', 'hllh8m1l605jp1is')
MYSQL_HOST = os.getenv('MYSQL_HOST', 'm7wltxurw8d2n21q.cbetxkdyhwsb.us-east-1.rds.amazonaws.com')
MYSQL_DB = os.getenv('MYSQL_DB', 'l8p7bk55le9p4st2')

def get_db_connection():
    connection = mysql.connector.connect(
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        host=MYSQL_HOST,
        database=MYSQL_DB
    )
    return connection

@app.before_request
def before_request():
    g.db = get_db_connection()
    g.cursor = g.db.cursor(dictionary=True)

@app.teardown_request
def teardown_request(exception):
    g.cursor.close()
    g.db.close()

def sanitize_input(input):
    return html.escape(input)

def get_user_id(username):
    g.cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
    user = g.cursor.fetchone()
    return user['id'] if user else None

def get_user(user_id):
    g.cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    return g.cursor.fetchone()

def create_user(username, password):
    hashed_password = generate_password_hash(password)
    g.cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
    g.db.commit()
    return g.cursor.lastrowid

def create_post(user_id, content):
    g.cursor.execute('INSERT INTO posts (user_id, content, upvotes, downvotes) VALUES (%s, %s, 0, 0)', (user_id, sanitize_input(content)))
    g.db.commit()
    return g.cursor.lastrowid

def flash_message(category, message):
    flash(message, category)

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/')
def index():
    if 'username' in session:
        g.cursor.execute('SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY (upvotes - downvotes) DESC')
        posts = g.cursor.fetchall()
        g.cursor.execute('SELECT post_id, vote FROM votes WHERE user_id = %s', (session['user_id'],))
        user_votes = {vote['post_id']: vote['vote'] for vote in g.cursor.fetchall()}
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
            user_id = session['user_id']
            post_id = create_post(user_id, content)
            flash_message('success', 'Post created successfully')
            return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    g.cursor.execute('SELECT * FROM posts WHERE id = %s AND user_id = %s', (post_id, user_id))
    post = g.cursor.fetchone()
    if post:
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
    g.cursor.execute('INSERT INTO comments (post_id, user_id, content) VALUES (%s, %s, %s)', (post_id, user_id, content))
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
