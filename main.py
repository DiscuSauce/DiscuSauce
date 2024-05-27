import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin
import html
import redis
import json

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci')

# Redis configuration
r = redis.Redis(
  host='redis-16989.c11.us-east-1-2.ec2.redns.redis-cloud.com',
  port=16989,
  password='uo9iVA7KLndbJRy3IK3NcjLWL5eYqcus'
)

@app.before_request
def before_request():
    g.redis = r

def sanitize_input(input):
    return html.escape(input)

def get_user_id(username):
    user_data = r.get(f"user:{username}")
    if user_data:
        user = json.loads(user_data)
        return user['id']
    return None

def get_user(user_id):
    user_data = r.get(f"user:id:{user_id}")
    if user_data:
        user = json.loads(user_data)
        return user
    return None

def create_user(username, password):
    user_id = r.incr("next_user_id")
    hashed_password = generate_password_hash(password)
    user = {'id': user_id, 'username': username, 'password': hashed_password}
    r.set(f"user:{username}", json.dumps(user))
    r.set(f"user:id:{user_id}", json.dumps(user))
    return user_id

def create_post(user_id, content):
    post_id = r.incr("next_post_id")
    post = {'id': post_id, 'user_id': user_id, 'content': content, 'upvotes': 0, 'downvotes': 0}
    r.set(f"post:{post_id}", json.dumps(post))
    r.lpush("posts", post_id)
    return post_id

@app.route('/')
def index():
    if 'username' in session:
        posts = []
        post_ids = r.lrange("posts", 0, -1)
        for post_id in post_ids:
            post_data = r.get(f"post:{post_id.decode('utf-8')}")
            if post_data:
                post = json.loads(post_data)
                post['user_info'] = get_user(post['user_id'])
                posts.append(post)
        return render_template('index.html', username=session['username'], posts=posts)
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
            flash('Username must be at least 3 characters long', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
        else:
            if get_user_id(username):
                flash('Username already exists', 'error')
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
            flash('Username must be at least 3 characters long', 'error')
        elif new_username:
            if get_user_id(new_username):
                flash('Username already exists', 'error')
            else:
                user = get_user(user_id)
                r.delete(f"user:{user['username']}")
                user['username'] = new_username
                session['username'] = new_username
                r.set(f"user:{new_username}", json.dumps(user))
                r.set(f"user:id:{user_id}", json.dumps(user))
                flash('Username updated successfully', 'success')
        if new_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'error')
            elif new_password != confirm_password:
                flash('Passwords do not match', 'error')
            else:
                user = get_user(user_id)
                user['password'] = generate_password_hash(new_password)
                r.set(f"user:{user['username']}", json.dumps(user))
                r.set(f"user:id:{user_id}", json.dumps(user))
                flash('Password updated successfully', 'success')
    user = get_user(user_id)
    return render_template('profile.html', username=user['username'])

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

@app.route('/post/<int:post_id>', methods=['GET'])
def view_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    post_data = r.get(f"post:{post_id}")
    if post_data:
        post = json.loads(post_data)
        post['user_info'] = get_user(post['user_id'])
        comments = []
        comment_ids = r.lrange(f"comments:{post_id}", 0, -1)
        for comment_id in comment_ids:
            comment_data = r.get(f"comment:{comment_id.decode('utf-8')}")
            if comment_data:
                comment = json.loads(comment_data)
                comment['user_info'] = get_user(comment['user_id'])
                comments.append(comment)
        return render_template('view_post.html', post=post, comments=comments)
    return redirect(url_for('index'))

@app.route('/upvote/<int:post_id>', methods=['POST'])
def upvote(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    post_data = r.get(f"post:{post_id}")
    if post_data:
        post = json.loads(post_data)
        post['upvotes'] += 1
        r.set(f"post:{post_id}", json.dumps(post))
    return redirect(url_for('index'))

@app.route('/downvote/<int:post_id>', methods=['POST'])
def downvote(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    post_data = r.get(f"post:{post_id}")
    if post_data:
        post = json.loads(post_data)
        post['downvotes'] += 1
        r.set(f"post:{post_id}", json.dumps(post))
    return redirect(url_for('index'))

@app.route('/delete/<int:post_id>', methods=['POST'])
def delete(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    r.delete(f"post:{post_id}")
    r.lrem("posts", 0, post_id)
    r.delete(f"comments:{post_id}")
    return redirect(url_for('index'))

@app.route('/comment/<int:post_id>', methods=['POST'])
def comment(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    content = request.form['content']
    content = sanitize_input(content)
    comment_id = r.incr("next_comment_id")
    comment = {'id': comment_id, 'post_id': post_id, 'user_id': session['user_id'], 'content': content}
    r.set(f"comment:{comment_id}", json.dumps(comment))
    r.lpush(f"comments:{post_id}", comment_id)
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
