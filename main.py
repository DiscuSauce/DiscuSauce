import redis
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import json

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
    exit(1)  # Exit the application if Redis connection fails

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
        user_id = r.get(f'username:{username}')
        if user_id:
            user = r.hgetall(f'user:{user_id}')
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
            hashed_password = generate_password_hash(password)
            if r.get(f'username:{username}'):
                flash('Username already exists', 'error')
            else:
                user_id = r.incr('user:id')
                user_data = {'username': username, 'password': hashed_password}
                r.hmset(f'user:{user_id}', user_data)
                r.set(f'username:{username}', user_id)
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
            if r.get(f'username:{new_username}'):
                flash('Username already exists', 'error')
            else:
                old_username = r.hget(f'user:{user_id}', 'username')
                user_data = {'username': new_username}
                r.hmset(f'user:{user_id}', user_data)
                r.delete(f'username:{old_username}')
                r.set(f'username:{new_username}', user_id)
                session['username'] = new_username
                flash('Username updated successfully', 'success')
        if new_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'error')
            elif new_password != confirm_password:
                flash('Passwords do not match', 'error')
            else:
                hashed_password = generate_password_hash(new_password)
                user_data = {'password': hashed_password}
                r.hmset(f'user:{user_id}', user_data)
                flash('Password updated successfully', 'success')
    user_posts = [r.hgetall(f'post:{post_id}') for post_id in r.smembers(f'user:{user_id}:posts')]
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
            post_id = r.incr('post:id')  # Get a new post ID
            post_data = {'user_id': user_id, 'content': content, 'upvotes': 0, 'downvotes': 0}
            r.hmset(f'post:{post_id}', post_data)
            r.lpush('posts', post_id)
            flash('Post created successfully', 'success')
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
        flash('Post deleted successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/vote/<int:post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    post = r.hgetall(f'post:{post_id}')
    if post:
        if vote == 1:
            r.hincrby(f'post:{post_id}', 'upvotes', 1)
        elif vote == -1:
            r.hincrby(f'post:{post_id}', 'downvotes', 1)
        flash('Vote registered successfully', 'success')
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if 'username' not in session or not session['admin']:
        return redirect(url_for('login'))
    users = [r.hgetall(f'user:{user_id}') for user_id in r.smembers('users')]
    posts = [r.hgetall(f'post:{post_id}') for post_id in r.lrange('posts', 0, -1)]
    return render_template('admin.html', users=users, posts=posts)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session or not session['admin']:
        return redirect(url_for('login'))
    if r.sismember('users', user_id):
        r.srem('users', user_id)
        r.delete(f'user:{user_id}')
        posts = r.smembers(f'user:{user_id}:posts')
        for post_id in posts:
            r.delete(f'post:{post_id}')
            r.lrem('posts', 0, post_id)
        flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('admin', None)
    return redirect(url_for('index'))

@app.route('/', methods=['GET', 'POST'])
def index():
    posts = [r.hgetall(f'post:{post_id}') for post_id in r.lrange('posts', 0, -1)]
    return render_template('index.html', posts=posts)

if __name__ == '__main__':
    app.run(debug=True)
