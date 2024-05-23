import redis
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from redis import ConnectionPool, StrictRedis

app = Flask(__name__)
app.secret_key = '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci'

# Configuration for Redis
redis_host = 'eu1-secure-albacore-38686.upstash.io'
redis_port = 38686
redis_password = '61ec78bf004a425a8eeb3555735646d7'

# Configure Redis connection pool
redis_pool = ConnectionPool(host=redis_host, port=redis_port, password=redis_password, ssl=True)

# Create Redis connection using the connection pool
r = StrictRedis(connection_pool=redis_pool)

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
                flash('Username updated successfully', 'success')
        if new_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'error')
            elif new_password != confirm_password:
                flash('Passwords do not match', 'error')
            else:
                hashed_password = generate_password_hash(new_password)
                r.hset(f'user:{user_id}', 'password', hashed_password)
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
            r.hmset(f'post:{post_id}', {'user_id': user_id, 'content': content, 'upvotes': 0, 'downvotes': 0})
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
    
    user_votes = {post_id: r.hget(f'vote:{post_id}:{session["user_id"]}', 'vote') for post_id in r.smembers('posts')}
    
    return render_template('view_post.html', post=post, comments=comments, user_votes=user_votes, username=session.get('username'))

@app.route('/delete_comment/int:comment_id')
def delete_comment(comment_id):
if 'username' not in session:
return redirect(url_for('login'))
user_id = session['user_id']
comment = r.hgetall(f'comment:{comment_id}')
if comment and comment['user_id'] == str(user_id):
r.delete(f'comment:{comment_id}')
r.srem(f'post:{comment["post_id"]}:comments', comment_id)
flash('Comment deleted successfully', 'success')
return redirect(url_for('view_post', post_id=comment['post_id']))

@app.route('/logout')
def logout():
session.pop('username', None)
session.pop('user_id', None)
session.pop('admin', None)
return redirect(url_for('login'))

@app.route('/create_comment/int:post_id', methods=['POST'])
def create_comment(post_id):
if 'username' not in session:
return redirect(url_for('login'))
content = request.form['comment']
user_id = session['user_id']
comment_id = r.incr('comment:id')
r.hmset(f'comment:{comment_id}', {'post_id': post_id, 'user_id': user_id, 'content': content})
r.sadd(f'post:{post_id}:comments', comment_id)
flash('Comment added successfully', 'success')
return redirect(url_for('view_post', post_id=post_id))

@app.route('/admin')
def admin():
if 'username' not in session or not session.get('admin'):
return redirect(url_for('login'))
users = [{'id': user_id, 'username': r.hget(f'user:{user_id}', 'username')} for user_id in r.keys('user:*') if user_id != 'user:id']
posts = [{'id': post_id, 'content': r.hget(f'post:{post_id}', 'content')} for post_id in r.smembers('posts')]
return render_template('admin.html', users=users, posts=posts)

@app.route('/delete_user/int:user_id')
def delete_user(user_id):
if 'username' not in session or not session.get('admin'):
return redirect(url_for('login'))
username = r.hget(f'user:{user_id}', 'username')
r.delete(f'username:{username}')
r.delete(f'user:{user_id}')
flash('User deleted successfully', 'success')
return redirect(url_for('admin'))

@app.route('/admin_delete_post/int:post_id')
def admin_delete_post(post_id):
if 'username' not in session or not session.get('admin'):
return redirect(url_for('login'))
r.delete(f'post:{post_id}')
r.srem('posts', post_id)
flash('Post deleted successfully', 'success')
return redirect(url_for('admin'))

@app.errorhandler(Exception)
def handle_exception(e):
print(f"Error: {e}")
return str(e), 500

if name == 'main':
app.run(debug=True, host='0.0.0.0')
