from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import redis
import os

app = Flask(__name__)
app.secret_key = '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci'

# Initialize Redis connection
r = redis.Redis(
    host='eu1-secure-albacore-38686.upstash.io',
    port=38686,
    password='61ec78bf004a425a8eeb3555735646d7',
    ssl=True
)

@app.before_request
def before_request():
    g.redis = r

@app.route('/')
def index():
    if 'username' in session:
        posts = g.redis.lrange('posts', 0, -1)
        posts = [eval(post) for post in posts]
        posts = sorted(posts, key=lambda x: x['upvotes'] - x['downvotes'], reverse=True)
        user_votes = {int(post_id): int(vote) for post_id, vote in g.redis.hgetall(f'user:{session["user_id"]}:votes').items()}
        return render_template('index.html', username=session['username'], posts=posts, user_votes=user_votes)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = g.redis.hgetall(f'user:{username}')
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
            user_id = g.redis.incr('user:id')
            user = {'id': user_id, 'username': username, 'password': hashed_password}
            if not g.redis.exists(f'user:{username}'):
                g.redis.hset(f'user:{username}', mapping=user)
                session['username'] = username
                session['user_id'] = user_id
                if username == 'admin':
                    session['admin'] = True
                return redirect(url_for('index'))
            else:
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
            if not g.redis.exists(f'user:{new_username}'):
                g.redis.hset(f'user:{new_username}', mapping=g.redis.hgetall(f'user:{session["username"]}'))
                g.redis.delete(f'user:{session["username"]}')
                session['username'] = new_username
                flash('Username updated successfully', 'success')
            else:
                flash('Username already exists', 'error')
        if new_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'error')
            elif new_password != confirm_password:
                flash('Passwords do not match', 'error')
            else:
                hashed_password = generate_password_hash(new_password)
                g.redis.hset(f'user:{session["username"]}', 'password', hashed_password)
                flash('Password updated successfully', 'success')
    user_posts = [eval(post) for post in g.redis.lrange(f'user:{user_id}:posts', 0, -1)]
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
            post_id = g.redis.incr('post:id')
            post = {'id': post_id, 'user_id': user_id, 'content': content, 'upvotes': 0, 'downvotes': 0}
            g.redis.lpush('posts', str(post))
            g.redis.lpush(f'user:{user_id}:posts', str(post))
            flash('Post created successfully', 'success')
            return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    posts = [eval(post) for post in g.redis.lrange('posts', 0, -1)]
    post = next((post for post in posts if post['id'] == post_id and post['user_id'] == user_id), None)
    if post:
        g.redis.lrem('posts', 0, str(post))
        g.redis.lrem(f'user:{user_id}:posts', 0, str(post))
        comments = g.redis.lrange(f'post:{post_id}:comments', 0, -1)
        for comment in comments:
            g.redis.delete(f'comment:{comment}')
        g.redis.delete(f'post:{post_id}:comments')
        flash('Post deleted successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/vote/<int:post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    post = eval(g.redis.lindex('posts', post_id - 1))
    existing_vote = g.redis.hget(f'user:{user_id}:votes', post_id)
    if existing_vote:
        if int(existing_vote) == vote:
            g.redis.hdel(f'user:{user_id}:votes', post_id)
            if vote == 1:
                post['upvotes'] -= 1
            else:
                post['downvotes'] -= 1
        else:
            g.redis.hset(f'user:{user_id}:votes', post_id, vote)
            if vote == 1:
                post['upvotes'] += 1
                post['downvotes'] -= 1
            else:
                post['upvotes'] -= 1
                post['downvotes'] += 1
    else:
        g.redis.hset(f'user:{user_id}:votes', post_id, vote)
        if vote == 1:
            post['upvotes'] += 1
        else:
            post['downvotes'] += 1
    g.redis.lset('posts', post_id - 1, str(post))
    return redirect(url_for('index'))

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        comment_content = request.form['comment']
        if comment_content:
            user_id = session['user_id']
            comment_id = g.redis.incr('comment:id')
            comment = {'id': comment_id, 'post_id': post_id, 'user_id': user_id, 'content': comment_content}
            g.redis.lpush(f'post:{post_id}:comments', str(comment))
            flash('Comment added successfully', 'success')
    post = eval(g.redis.lindex('posts', post_id - 1))
    comments = [eval(comment) for comment in g.redis.lrange(f'post:{post_id}:comments', 0, -1)]
    user_votes = {int(post_id): int(vote) for post_id, vote in g.redis.hgetall(f'user:{session["user_id"]}:votes').items()}
    return render_template('view_post.html', post=post, comments=comments, user_votes=user_votes)

@app.route('/delete_comment/<int:comment_id>/<int:post_id>')
def delete_comment(comment_id, post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    comment = eval(g.redis.get(f'comment:{comment_id}'))
    if comment and comment['user_id'] == session['user_id']:
        g.redis.lrem(f'post:{post_id}:comments', 0, str(comment))
        g.redis.delete(f'comment:{comment_id}')
        flash('Comment deleted successfully', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('admin', None)
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    users = [eval(user) for user in g.redis.lrange('users', 0, -1)]
    posts = [eval(post) for post in g.redis.lrange('posts', 0, -1)]
    return render_template('admin.html', users=users, posts=posts)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    user = eval(g.redis.get(f'user:{user_id}'))
    if user:
        g.redis.delete(f'user:{user_id}')
        g.redis.lrem('users', 0, str(user))
        flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin_delete_post/<int:post_id>')
def admin_delete_post(post_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    post = eval(g.redis.lindex('posts', post_id - 1))
    if post:
        g.redis.lrem('posts', 0, str(post))
        comments = g.redis.lrange(f'post:{post_id}:comments', 0, -1)
        for comment in comments:
            g.redis.delete(f'comment:{comment}')
        g.redis.delete(f'post:{post_id}:comments')
        flash('Post deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.errorhandler(Exception)
def handle_exception(e):
    print(f"Error: {e}")
    return str(e), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
