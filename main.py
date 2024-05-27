from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin
import html
import os
import redis
from flask import Flask, request, session, g, redirect, url_for, flash, render_template

app = Flask(__name__)
app.secret_key = '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci'

# Redis configuration
r = redis.Redis(
  host='redis-16989.c11.us-east-1-2.ec2.redns.redis-cloud.com',
  port=16989,
  password='uo9iVA7KLndbJRy3IK3NcjLWL5eYqcus'
)

def init_db():
    # No explicit schema creation needed for Redis, as it is schemaless
    pass

@app.before_first_request
def before_first_request():
    init_db()

@app.before_request
def before_request():
    g.db = r

def sanitize_input(input):
    return html.escape(input)

def get_user_id(username):
    user_id = g.db.get(f"user:username:{username}")
    return int(user_id) if user_id else None

def get_user(user_id):
    user_data = g.db.hgetall(f"user:{user_id}")
    if user_data:
        return {k.decode(): v.decode() for k in user_data}
    return None

def create_user(username, password):
    user_id = g.db.incr("user:id")
    hashed_password = generate_password_hash(password)
    g.db.hmset(f"user:{user_id}", {"username": username, "password": hashed_password})
    g.db.set(f"user:username:{username}", user_id)
    return user_id

def create_post(user_id, content):
    post_id = g.db.incr("post:id")
    g.db.hmset(f"post:{post_id}", {"user_id": user_id, "content": sanitize_input(content), "upvotes": 0, "downvotes": 0})
    g.db.lpush(f"user:{user_id}:posts", post_id)
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
        post_ids = g.db.lrange("posts", 0, -1)
        posts = [g.db.hgetall(f"post:{post_id.decode()}") for post_id in post_ids]
        for post in posts:
            post['username'] = g.db.hget(f"user:{post['user_id'].decode()}", "username").decode()
        user_votes = {int(k.decode()): int(v.decode()) for k, v in g.db.hgetall(f"user:{session['user_id']}:votes").items()}
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
                g.db.hset(f"user:{user_id}", "username", new_username)
                g.db.delete(f"user:username:{old_username}")
                g.db.set(f"user:username:{new_username}", user_id)
                session['username'] = new_username
                flash_message('success', 'Username updated successfully')
        if new_password:
            if len(new_password) < 8:
                flash_message('error', 'Password must be at least 8 characters long')
            elif new_password != confirm_password:
                flash_message('error', 'Passwords do not match')
            else:
                hashed_password = generate_password_hash(new_password)
                g.db.hset(f"user:{user_id}", "password", hashed_password)
                flash_message('success', 'Password updated successfully')
    user_posts = [g.db.hgetall(f"post:{post_id.decode()}") for post_id in g.db.lrange(f"user:{user_id}:posts", 0, -1)]
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
            g.db.lpush("posts", post_id)
            flash_message('success', 'Post created successfully')
            return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    post = g.db.hgetall(f"post:{post_id}")
    if post and int(post['user_id'].decode()) == user_id:
        g.db.delete(f"post:{post_id}")
        g.db.lrem(f"user:{user_id}:posts", 0, post_id)
        g.db.lrem("posts", 0, post_id)
        flash_message('success', 'Post deleted successfully')
    else:
        flash_message('error', 'You are not authorized to delete this post')
    return redirect(url_for('profile'))

@app.route('/vote/<int:post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    existing_vote = g.db.hget(f"user:{user_id}:votes", post_id)
    post_key = f"post:{post_id}"
    if existing_vote:
        existing_vote = int(existing_vote.decode())
        if existing_vote == vote:
            g.db.hdel(f"user:{user_id}:votes", post_id)
            g.db.hincrby(post_key, 'upvotes' if vote == 1 else 'downvotes', -1)
        else:
            g.db.hset(f"user:{user_id}:votes", post_id, vote)
            g.db.hincrby(post_key, 'upvotes', 1 if vote == 1 else -1)
            g.db.hincrby(post_key, 'downvotes', -1 if vote == 1 else 1)
    else:
        g.db.hset(f"user:{user_id}:votes", post_id, vote)
        g.db.hincrby(post_key, 'upvotes' if vote == 1 else 'downvotes', 1)
    return redirect(url_for('index'))

@app.route('/view_post/<int:post_id>')
def view_post(post_id):
    post = g.db.hgetall(f"post:{post_id}")
    if not post:
        return 'Post not found', 404
    post['username'] = g.db.hget(f"user:{post['user_id'].decode()}", "username").decode()
    comment_ids = g.db.lrange(f"post:{post_id}:comments", 0, -1)
    comments = [g.db.hgetall(f"comment:{comment_id.decode()}") for comment_id in comment_ids]
    for comment in comments:
        comment['username'] = g.db.hget(f"user:{comment['user_id'].decode()}", "username").decode()
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
    comment_id = g.db.incr("comment:id")
    g.db.hmset(f"comment:{comment_id}", {"post_id": post_id, "user_id": user_id, "content": content})
    g.db.lpush(f"post:{post_id}:comments", comment_id)
    flash('Comment added successfully', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/admin')
def admin():
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    user_keys = g.db.keys("user:*")
    users = [{k.decode(): v.decode() for k, v in g.db.hgetall(user_key).items()} for user_key in user_keys if b':' not in user_key]
    post_keys = g.db.keys("post:*")
    posts = [{k.decode(): v.decode() for k, v in g.db.hgetall(post_key).items()} for post_key in post_keys if b':' not in post_key]
    return render_template('admin.html', users=users, posts=posts)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    username = g.db.hget(f"user:{user_id}", "username").decode()
    g.db.delete(f"user:{user_id}")
    g.db.delete(f"user:username:{username}")
    user_posts = g.db.lrange(f"user:{user_id}:posts", 0, -1)
    for post_id in user_posts:
        g.db.delete(f"post:{post_id.decode()}")
        g.db.lrem("posts", 0, post_id)
    g.db.delete(f"user:{user_id}:posts")
    g.db.delete(f"user:{user_id}:votes")
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin_delete_post/<int:post_id>')
def admin_delete_post(post_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    post = g.db.hgetall(f"post:{post_id}")
    if post:
        g.db.delete(f"post:{post_id}")
        g.db.lrem("posts", 0, post_id)
        user_id = int(post['user_id'].decode())
        g.db.lrem(f"user:{user_id}:posts", 0, post_id)
    flash('Post deleted successfully', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
