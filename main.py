import os
import psycopg2
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import quote as url_quote

app = Flask(__name__)
app.secret_key = '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci'

DATABASE_URL = 'postgres://otsmcreckptmxm:6c840cfd7e13bf4e4168aa8fb4466ec5ab2cba6bb766b82f785c2462773f0817@ec2-34-251-236-65.eu-west-1.compute.amazonaws.com:5432/d192qeh4mntrks'

def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(DATABASE_URL, sslmode='require')
    return g.db

def init_db():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users
                          (id SERIAL PRIMARY KEY, 
                           username TEXT UNIQUE, 
                           password TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS posts
                          (id SERIAL PRIMARY KEY, 
                           user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
                           content TEXT, 
                           upvotes INTEGER DEFAULT 0, 
                           downvotes INTEGER DEFAULT 0)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS comments
                          (id SERIAL PRIMARY KEY, 
                           post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, 
                           user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
                           content TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS votes
                          (id SERIAL PRIMARY KEY, 
                           post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, 
                           user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, 
                           vote INTEGER, 
                           UNIQUE(post_id, user_id))''')
        db.commit()
        cursor.close()
        print("Tables created successfully.")
    except Exception as e:
        print(f"Error creating tables: {e}")

init_db()

@app.before_request
def before_request():
    g.db = get_db()

@app.teardown_request
def teardown_request(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    if 'username' in session:
        cursor = g.db.cursor()
        cursor.execute('''
            SELECT posts.id, users.username, posts.content, posts.upvotes, posts.downvotes
            FROM posts JOIN users ON posts.user_id = users.id
            ORDER BY (posts.upvotes - posts.downvotes) DESC
        ''')
        posts = cursor.fetchall()
        cursor.execute('SELECT post_id, vote FROM votes WHERE user_id = %s', (session['user_id'],))
        user_votes = {row[0]: row[1] for row in cursor.fetchall()}
        cursor.close()
        return render_template('index.html', username=session['username'], posts=posts, user_votes=user_votes)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = g.db.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        if user and check_password_hash(user[2], password):
            session['username'] = username
            session['user_id'] = user[0]
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
                cursor = g.db.cursor()
                cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
                g.db.commit()
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                user = cursor.fetchone()
                session['username'] = username
                session['user_id'] = user[0]
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
                cursor = g.db.cursor()
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
                cursor = g.db.cursor()
                cursor.execute('UPDATE users SET password = %s WHERE id = %s', (hashed_password, user_id))
                g.db.commit()
                flash('Password updated successfully', 'success')
    cursor = g.db.cursor()
    cursor.execute('SELECT id, content FROM posts WHERE user_id = %s', (user_id,))
    user_posts = cursor.fetchall()
    cursor.close()
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
            cursor = g.db.cursor()
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
    cursor = g.db.cursor()
    cursor.execute('SELECT * FROM posts WHERE id = %s AND user_id = %s', (post_id, user_id))
    post = cursor.fetchone()
    if post:
        cursor.execute('DELETE FROM posts WHERE id = %s', (post_id,))
        cursor.execute('DELETE FROM comments WHERE post_id = %s', (post_id,))
        cursor.execute('DELETE FROM votes WHERE post_id = %s', (post_id,))
        g.db.commit()
        flash('Post deleted successfully', 'success')
    cursor.close()
    return redirect(url_for('profile'))

@app.route('/vote/<int:post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    cursor = g.db.cursor()
    cursor.execute('SELECT * FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user_id))
    existing_vote = cursor.fetchone()
    if existing_vote:
        if existing_vote[3] == vote:
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
    cursor.close()
    return redirect(url_for('index'))

@app.route('/create_comment/<int:post_id>', methods=['POST'])
def create_comment(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    content = request.form['content']
    user_id = session['user_id']
    cursor = g.db.cursor()
    cursor.execute('INSERT INTO comments (post_id, user_id, content) VALUES (%s, %s, %s)', (post_id, user_id, content))
    g.db.commit()
    cursor.close()
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'admin' not in session:
        return redirect(url_for('index'))
    cursor = g.db.cursor()
    cursor.execute('SELECT id, username FROM users')
    users = cursor.fetchall()
    if request.method == 'POST':
        username = request.form['username']
        cursor.execute('DELETE FROM users WHERE username = %s', (username,))
        g.db.commit()
        flash(f'User {username} deleted successfully', 'success')
    cursor.close()
    return render_template('admin.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)
