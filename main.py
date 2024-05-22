from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import psycopg2
from psycopg2.extras import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci'

def get_db_connection():
    result = urlparse(os.getenv('DATABASE_URL'))
    username = result.username
    password = result.password
    database = result.path[1:]
    hostname = result.hostname
    port = result.port

    return psycopg2.connect(
        database=database,
        user=username,
        password=password,
        host=hostname,
        port=port,
        cursor_factory=DictCursor
    )

def init_db():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('''CREATE TABLE IF NOT EXISTS users
                          (id SERIAL PRIMARY KEY, 
                           username TEXT UNIQUE, 
                           password TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS posts
                          (id SERIAL PRIMARY KEY, 
                           user_id INTEGER, 
                           content TEXT, 
                           upvotes INTEGER DEFAULT 0, 
                           downvotes INTEGER DEFAULT 0, 
                           FOREIGN KEY(user_id) REFERENCES users(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS comments
                          (id SERIAL PRIMARY KEY, 
                           post_id INTEGER, 
                           user_id INTEGER, 
                           content TEXT, 
                           FOREIGN KEY(post_id) REFERENCES posts(id), 
                           FOREIGN KEY(user_id) REFERENCES users(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS votes
                          (id SERIAL PRIMARY KEY, 
                           post_id INTEGER, 
                           user_id INTEGER, 
                           vote INTEGER, 
                           UNIQUE(post_id, user_id), 
                           FOREIGN KEY(post_id) REFERENCES posts(id), 
                           FOREIGN KEY(user_id) REFERENCES users(id))''')
        conn.commit()
    conn.close()

@app.before_request
def before_request():
    g.db = get_db_connection()

@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()

@app.route('/')
def index():
    if 'username' in session:
        with g.db.cursor() as cursor:
            cursor.execute('''
                SELECT posts.id, users.username, posts.content, posts.upvotes, posts.downvotes
                FROM posts JOIN users ON posts.user_id = users.id
                ORDER BY (posts.upvotes - posts.downvotes) DESC
            ''')
            posts = cursor.fetchall()
            cursor.execute('SELECT post_id, vote FROM votes WHERE user_id = %s', (session['user_id'],))
            user_votes = {row['post_id']: row['vote'] for row in cursor.fetchall()}
        return render_template('index.html', username=session['username'], posts=posts, user_votes=user_votes)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with g.db.cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password'], password):
                session['username'] = username
                session['user_id'] = user['id']
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
            flash('Username must be at least 3 characters long', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
        else:
            hashed_password = generate_password_hash(password)
            try:
                with g.db.cursor() as cursor:
                    cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
                    g.db.commit()
                    session['username'] = username
                    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                    user = cursor.fetchone()
                    session['user_id'] = user['id']
                    if username == 'admin':
                        session['admin'] = True
                    return redirect(url_for('index'))
            except psycopg2.IntegrityError:
                g.db.rollback()
                flash('Username already exists', 'error')
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
            flash('Username must be at least 3 characters long', 'error')
        elif new_username:
            try:
                with g.db.cursor() as cursor:
                    cursor.execute('UPDATE users SET username = %s WHERE id = %s', (new_username, user_id))
                    g.db.commit()
                    session['username'] = new_username
                    flash('Username updated successfully', 'success')
            except psycopg2.IntegrityError:
                g.db.rollback()
                flash('Username already exists', 'error')
        if new_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'error')
            elif new_password != confirm_password:
                flash('Passwords do not match', 'error')
            else:
                hashed_password = generate_password_hash(new_password)
                with g.db.cursor() as cursor:
                    cursor.execute('UPDATE users SET password = %s WHERE id = %s', (hashed_password, user_id))
                    g.db.commit()
                flash('Password updated successfully', 'success')
    with g.db.cursor() as cursor:
        cursor.execute('SELECT id, content FROM posts WHERE user_id = %s', (user_id,))
        user_posts = cursor.fetchall()
    return render_template('profile.html', posts=user_posts)

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form['content']
        if len(content.split()) > 64:
            flash('Post content exceeds 64 words limit', 'error')
        else:
            user_id = session['user_id']
            with g.db.cursor() as cursor:
                cursor.execute('INSERT INTO posts (user_id, content) VALUES (%s, %s)', (user_id, content))
                g.db.commit()
            flash('Post created successfully', 'success')
            return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    with g.db.cursor() as cursor:
        cursor.execute('SELECT * FROM posts WHERE id = %s AND user_id = %s', (post_id, user_id))
        post = cursor.fetchone()
        if post:
            cursor.execute('DELETE FROM posts WHERE id = %s', (post_id,))
            cursor.execute('DELETE FROM comments WHERE post_id = %s', (post_id,))
            cursor.execute('DELETE FROM votes WHERE post_id = %s', (post_id,))
            g.db.commit()
            flash('Post deleted successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/vote/<int:post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    with g.db.cursor() as cursor:
        cursor.execute('SELECT * FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user_id))
        existing_vote = cursor.fetchone()
        if existing_vote:
            if existing_vote['vote'] == vote:
                cursor.execute('DELETE FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user_id))
                if vote == 1:
                    cursor.execute('UPDATE posts SET upvotes = upvotes - 1 WHERE id = %s', (post_id,))
                else:
                    cursor.execute('UPDATE posts SET downvotes = downvotes - 1 WHERE id = %s', (post_id,))
            else:
                                cursor.execute('UPDATE votes SET vote = %s WHERE post_id = %s AND user_id = %s', (vote, post_id, user_id))
                if vote == 1:
                    cursor.execute('UPDATE posts SET upvotes = upvotes + 1, downvotes = downvotes - 1 WHERE id = %s', (post_id,))
                else:
                    cursor.execute('UPDATE posts SET upvotes = upvotes - 1, downvotes = downvotes + 1 WHERE id = %s', (post_id,))
        else:
            cursor.execute('INSERT INTO votes (post_id, user_id, vote) VALUES (%s, %s, %s)', (post_id, user_id, vote))
            if vote == 1:
                cursor.execute('UPDATE posts SET upvotes = upvotes + 1 WHERE id = %s', (post_id,))
            else:
                cursor.execute('UPDATE posts SET downvotes = downvotes + 1 WHERE id = %s', (post_id,))
        g.db.commit()
    return redirect(url_for('index'))

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        comment_content = request.form['comment']
        if comment_content:
            user_id = session['user_id']
            with g.db.cursor() as cursor:
                cursor.execute('INSERT INTO comments (post_id, user_id, content) VALUES (%s, %s, %s)', (post_id, user_id, comment_content))
                g.db.commit()
            flash('Comment added successfully', 'success')
    with g.db.cursor() as cursor:
        cursor.execute('''
            SELECT posts.id, users.username, posts.content, posts.upvotes, posts.downvotes 
            FROM posts 
            JOIN users ON posts.user_id = users.id 
            WHERE posts.id = %s
        ''', (post_id,))
        post = cursor.fetchone()
        cursor.execute('''
            SELECT comments.id, users.username, comments.content 
            FROM comments 
            JOIN users ON comments.user_id = users.id 
            WHERE comments.post_id = %s
        ''', (post_id,))
        comments = cursor.fetchall()
        cursor.execute('SELECT post_id, vote FROM votes WHERE user_id = %s', (session['user_id'],))
        user_votes = {row['post_id']: row['vote'] for row in cursor.fetchall()}
    return render_template('view_post.html', post=post, comments=comments, user_votes=user_votes, username=session.get('username'))

@app.route('/delete_comment/<int:comment_id>')
def delete_comment(comment_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    with g.db.cursor() as cursor:
        cursor.execute('SELECT * FROM comments WHERE id = %s AND user_id = %s', (comment_id, user_id))
        comment = cursor.fetchone()
        if comment:
            cursor.execute('DELETE FROM comments WHERE id = %s', (comment_id,))
            g.db.commit()
            flash('Comment deleted successfully', 'success')
    return redirect(url_for('view_post', post_id=comment['post_id']))

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
    content = request.form['comment']
    user_id = session['user_id']
    with g.db.cursor() as cursor:
        cursor.execute('INSERT INTO comments (post_id, user_id, content) VALUES (%s, %s, %s)', (post_id, user_id, content))
        g.db.commit()
    flash('Comment added successfully', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/admin')
def admin():
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    with g.db.cursor() as cursor:
        cursor.execute('SELECT id, username FROM users')
        users = cursor.fetchall()
        cursor.execute('SELECT id, content FROM posts')
        posts = cursor.fetchall()
    return render_template('admin.html', users=users, posts=posts)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    with g.db.cursor() as cursor:
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        g.db.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin_delete_post/<int:post_id>')
def admin_delete_post(post_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    with g.db.cursor() as cursor:
        cursor.execute('DELETE FROM posts WHERE id = %s', (post_id,))
        g.db.commit()
    flash('Post deleted successfully', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
