import os
import psycopg2
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

DATABASE_URL = os.environ['DATABASE_URL']

def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(DATABASE_URL, sslmode='require')
    return g.db

def init_db():
    with app.app_context():
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
        posts = g.db.execute('''
            SELECT posts.id, users.username, posts.content, posts.upvotes, posts.downvotes
            FROM posts JOIN users ON posts.user_id = users.id
            ORDER BY (posts.upvotes - posts.downvotes) DESC
        ''').fetchall()
        user_votes = {row[0]: row[1] for row in g.db.execute('SELECT post_id, vote FROM votes WHERE user_id = ?', (session['user_id'],)).fetchall()}
        return render_template('index.html', username=session['username'], posts=posts, user_votes=user_votes)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = g.db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
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
                g.db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                g.db.commit()
                session['username'] = username
                user = g.db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                session['user_id'] = user[0]
                if username == 'admin':
                    session['admin'] = True
                return redirect(url_for('index'))
            except psycopg2.IntegrityError:
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
                g.db.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, user_id))
                g.db.commit()
                session['username'] = new_username
                flash('Username updated successfully', 'success')
            except psycopg2.IntegrityError:
                flash('Username already exists', 'error')
        if new_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'error')
            elif new_password != confirm_password:
                flash('Passwords do not match', 'error')
            else:
                hashed_password = generate_password_hash(new_password)
                g.db.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))
                g.db.commit()
                flash('Password updated successfully', 'success')
    user_posts = g.db.execute('SELECT id, content FROM posts WHERE user_id = ?', (user_id,)).fetchall()
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
            g.db.execute('INSERT INTO posts (user_id, content) VALUES (?, ?)', (user_id, content))
            g.db.commit()
            flash('Post created successfully', 'success')
            return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    post = g.db.execute('SELECT * FROM posts WHERE id = ? AND user_id = ?', (post_id, user_id)).fetchone()
    if post:
        g.db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        g.db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
        g.db.execute('DELETE FROM votes WHERE post_id = ?', (post_id,))
        g.db.commit()
        flash('Post deleted successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/vote/<int:post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    existing_vote = g.db.execute('SELECT * FROM votes WHERE post_id = ? AND user_id = ?', (post_id, user_id)).fetchone()
    if existing_vote:
        if existing_vote[3] == vote:
            g.db.execute('DELETE FROM votes WHERE post_id = ? AND user_id = ?', (post_id, user_id))
            if vote == 1:
                g.db.execute('UPDATE posts SET upvotes = upvotes - 1 WHERE id = ?', (post_id,))
            else:
                g.db.execute('UPDATE posts SET downvotes = downvotes - 1 WHERE id = ?', (post_id,))
        else:
            g.db.execute('UPDATE votes SET vote = ? WHERE post_id = ? AND user_id = ?', (vote, post_id, user_id))
            if vote == 1:
                g.db.execute('UPDATE posts SET upvotes = upvotes + 1, downvotes = downvotes - 1 WHERE id = ?', (post_id,))
            else:
                g.db.execute('UPDATE posts SET upvotes = upvotes - 1, downvotes = downvotes + 1 WHERE id = ?', (post_id,))
    else:
        g.db.execute('INSERT INTO votes (post_id, user_id, vote) VALUES (?, ?, ?)', (post_id, user_id, vote))
        if vote == 1:
            g.db.execute('UPDATE posts SET upvotes = upvotes + 1 WHERE id = ?', (post_id,))
        else:
            g.db.execute('UPDATE posts SET downvotes = downvotes + 1 WHERE id = ?', (post_id,))
    g.db.commit()
    return redirect(url_for('index'))

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        comment_content = request.form['comment']
        user_id = session['user_id']
        g.db.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)', (post_id, user_id, comment_content))
        g.db.commit()
        flash('Comment added successfully', 'success')
    post = g.db.execute('''
        SELECT posts.id, users.username, posts.content, posts.upvotes, posts.downvotes
        FROM posts JOIN users ON posts.user_id = users.id
        WHERE posts.id = ?
    ''', (post_id,)).fetchone()
    comments = g.db.execute('''
        SELECT comments.id, users.username, comments.content
        FROM comments JOIN users ON comments.user_id = users.id
        WHERE comments.post_id = ?
    ''', (post_id,)).fetchall()
    user_vote = g.db.execute('SELECT vote FROM votes WHERE post_id = ? AND user_id = ?', (post_id, session['user_id'])).fetchone()
    return render_template('view_post.html', post=post, comments=comments, user_vote=user_vote[0] if user_vote else None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
