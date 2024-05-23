import redis
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci'

# Configuration for Redis
redis_host = 'eu1-secure-albacore-38686.upstash.io'
redis_port = 38686
redis_password = '61ec78bf004a425a8eeb3555735646d7'

# Create Redis connection
r = None
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
    if r:
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
                r.hmset(f'user:{user_id}', {'username': username, 'password': hashed_password})
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
                r.hset(f'user:{user_id}', 'username', new_username)
                r.delete(f'username:{old_username}')
                r.set(f'username:{new_username}', user_id)
                session['username'] = new_username
        if new_password and len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'error')
        elif new_password and confirm_password:
            if new_password != confirm_password:
                flash('Passwords do not match', 'error')
            else:
                hashed_password = generate_password_hash(new_password)
                r.hset(f'user:{user_id}', 'password', hashed_password)
                flash('Profile updated', 'success')
    return render_template('profile.html', username=session['username'])

@app.route('/post', methods=['POST'])
def post():
    if 'username' not in session:
        return redirect(url_for('login'))
    title = request.form['title']
    body = request.form['body']
    if len(title) < 3:
        flash('Title must be at least 3 characters long', 'error')
    elif len(body) < 3:
        flash('Body must be at least 3 characters long', 'error')
    else:
        post_id = r.incr('post:id')
        r.hmset(f'post:{post_id}', {'user_id': session['user_id'], 'title': title, 'body': body, 'upvotes': 0, 'downvotes': 0})
        r.sadd('posts', post_id)
        flash('Post created', 'success')
    return redirect(url_for('index'))

@app.route('/upvote/<int:post_id>')
def upvote(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    vote = r.hget(f'vote:{post_id}:{session["user_id"]}', 'vote')
    if vote:
        if vote == '1':
            flash('You have already upvoted this post', 'error')
        else:
            r.hset(f'vote:{post_id}:{session["user_id"]}', 'vote', '1')
            r.hincrby(f'post:{post_id}', 'upvotes', 1)
            r.hincrby(f'post:{post_id}', 'downvotes', -1)
            flash('Upvoted', 'success')
    else:
        r.hset(f'vote:{post_id}:{session["user_id"]}', 'vote', '1')
        r.hincrby(f'post:{post_id}', 'upvotes', 1)
        flash('Upvoted', 'success')
    return redirect(url_for('index'))

@app.route('/downvote/<int:post_id>')
def downvote(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    vote = r.hget(f'vote:{post_id}:{session["user_id"]}', 'vote')
    if vote:
        if vote == '-1':
            flash('You have already downvoted this post', 'error')
        else:
            r.hset(f'vote:{post_id}:{session["user_id"]}', 'vote', '-1')
            r.hincrby(f'post:{post_id}', 'downvotes', 1)
            r.hincrby(f'post:{post_id}', 'upvotes', -1)
            flash('Downvoted', 'success')
    else:
        r.hset(f'vote:{post_id}:{session["user_id"]}', 'vote', '-1')
        r.hincrby(f'post:{post_id}', 'downvotes', 1)
        flash('Downvoted', 'success')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
