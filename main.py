import redis
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin
import html

app = Flask(__name__)
app.secret_key = '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci'

# Configuration for Redis
redis_host = 'eu1-secure-albacore-38686.upstash.io'
redis_port = 38686
redis_password = '61ec78bf004a425a8eeb3555735646d7'

# Create Redis connection
try:
    r = redis.StrictRedis(
        host=redis_host,
        port=redis_port,
        password=redis_password,
        ssl=True,
        decode_responses=True
    )
    # Test Redis connection
    r.ping()
    print("Connected to Redis successfully!")
except redis.ConnectionError as e:
    print(f"Redis connection failed: {e}")

def init_redis():
    try:
        r.flushdb()  # Clears the Redis database
        print("Redis database initialized.")
    except Exception as e:
        print(f"Failed to initialize Redis: {e}")

init_redis()

@app.before_request
def before_request():
    g.db = r

@app.teardown_request
def teardown_request(exception):
    pass  # Redis connection does not need to be closed

def sanitize_input(input):
    return html.escape(input)

def get_user_id(username):
    return r.get(f'username:{username}')

def get_user(user_id):
    return r.hgetall(f'user:{user_id}')

def create_user(username, password):
    user_id = r.incr('user:id')
    hashed_password = generate_password_hash(password)
    r.hset(f'user:{user_id}', mapping={'username': username, 'password': hashed_password})
    r.set(f'username:{username}', user_id)
    return user_id

def create_post(user_id, content):
    post_id = r.incr('post:id')
    r.hset(f'post:{post_id}', mapping={'user_id': user_id, 'content': sanitize_input(content), 'upvotes': 0, 'downvotes': 0})
    r.sadd('posts', post_id)
    r.sadd(f'user:{user_id}:posts', post_id)
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
        posts = []
        for post_id in r.smembers('posts'):
            post = r.hgetall(f'post:{post_id}')
            post['id'] = post_id
            post['username'] = r.hget(f'user:{post["user_id"]}', 'username')
            posts.append(post)
        posts.sort(key=lambda x: int(x['upvotes']) - int(x['downvotes']), reverse=True)
        user_votes = {post_id: r.hget(f'vote:{post_id}:{session["user_id"]}', 'vote') for post_id in r.smembers('posts')}
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
                old_username = r.hget(f'user:{user_id}', 'username')
                r.hset(f'user:{user_id}', 'username', new_username)
                r.delete(f'username:{old_username}')
                r.set(f'username:{new_username}', user_id)
                session['username'] = new_username
                flash_message('success', 'Username updated successfully')
        if new_password:
            if len(new_password) < 8:
                flash_message('error', 'Password must be at least 8 characters long')
            elif new_password != confirm_password:
                flash_message('error', 'Passwords do not match')
            else:
                hashed_password = generate_password_hash(new_password)
                r.hset(f'user:{user_id}', 'password', hashed_password)
                flash_message('success', 'Password updated successfully')
    user_posts = [r.hgetall(f'post:{post_id}') for post_id in r.smembers(f'user:{user_id}:posts')]
    return render_template('profile.html', posts=user_posts)

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'username' not in session:
        flash('You need to be logged in to create a post', 'error')
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
    post = r.hgetall(f'post:{post_id}')
    if post and post['user_id'] == str(user_id):
        r.delete(f'post:{post_id}')
        r.srem('posts', post_id)
        r.srem(f'user:{user_id}:posts', post_id)
        flash_message('success', 'Post deleted successfully')
    else:
        flash_message('error', 'You are not authorized to delete this post')
    return redirect(url_for('profile'))

@app.route('/vote/<int:post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    existing_vote = r.hget(f'vote:{post_id}:{user_id}', 'vote')
    if existing_vote:
        if int(existing_vote) == vote:
            r.delete(f'vote:{post_id}:{user_id}')
            if vote == 1:
                r.hincrby(f'post:{post_id}', 'upvotes', -1)
            else:
                r.hincrby(f'post:{post_id}', 'downvotes', -1)
        else:
            r.hset(f'vote:{post_id}:{user_id}', 'vote', vote)
            if vote == 1:
                r.hincrby(f'post:{post_id}', 'upvotes', 1)
                r.hincrby(f'post:{post_id}', 'downvotes', -1)
            else:
                r.hincrby(f'post:{post_id}', 'upvotes', -1)
                r.hincrby(f'post:{post_id}', 'downvotes', 1)
    else:
        r.hset(f'vote:{post_id}:{user_id}', 'vote', vote)
        if vote == 1:
            r.hincrby(f'post:{post_id}', 'upvotes', 1)
        else:
            r.hincrby(f'post:{post_id}', 'downvotes', 1)
    return redirect(url_for('index'))

@app.route('/view_post/<int:post_id>')
def view_post(post_id):
    post = r.hgetall(f'post:{post_id}')
    if not post:
        return 'Post not found', 404
    post['id'] = post_id
    post['username'] = r.hget(f'user:{post["user_id"]}', 'username')
    comments = []
    for comment_id in r.smembers(f'post:{post_id}:comments'):
        comment = r.hgetall(f'comment:{comment_id}')
        comment['id'] = comment_id
        comment['username'] = r.hget(f'user:{comment["user_id"]}', 'username')
        comments.append(comment)
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
    comment_id = r.incr('comment:id')
    r.hset(f'comment:{comment_id}', mapping={'post_id': post_id, 'user_id': user_id, 'content': content})
    r.sadd(f'post:{post_id}:comments', comment_id)
    flash('Comment added successfully', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/admin')
def admin():
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    users = [{'id': user_id.split(':')[1], 'username': r.hget(user_id, 'username')} for user_id in r.keys('user:*') if user_id != 'user:id']
    posts = [{'id': post_id, 'content': r.hget(f'post:{post_id}', 'content')} for post_id in r.smembers('posts')]
    return render_template('admin.html', users=users, posts=posts)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    username = r.hget(f'user:{user_id}', 'username')
    r.delete(f'username:{username}')
    r.delete(f'user:{user_id}')
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin_delete_post/<int:post_id>')
def admin_delete_post(post_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    r.delete(f'post:{post_id}')
    r.srem('posts', post_id)
    flash('Post deleted successfully', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)
