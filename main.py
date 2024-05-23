from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import redis
import os
import json

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '@@@qazaq@@@')

# Configure Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url(os.environ['UPSTASH_REDIS_REST_URL'])

# Initialize session
Session(app)

r = redis.from_url(os.environ['UPSTASH_REDIS_REST_URL'])

def get_user_id(username):
    user_id = r.get(f"user:id:{username.lower()}")
    if user_id:
        return int(user_id)
    return None

def get_username(user_id):
    username = r.get(f"user:username:{user_id}")
    if username:
        return username.decode('utf-8')
    return None

@app.route('/')
def index():
    if 'username' in session:
        posts = []
        for key in r.scan_iter("post:*"):
            post = json.loads(r.get(key))
            post['username'] = get_username(post['user_id'])
            posts.append(post)
        posts.sort(key=lambda x: (x['upvotes'] - x['downvotes']), reverse=True)
        user_votes = {int(post_id): int(vote) for post_id, vote in r.hgetall(f"user:votes:{session['user_id']}").items()}
        return render_template('index.html', username=session['username'], posts=posts, user_votes=user_votes)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_id = get_user_id(username)
        if user_id:
            stored_password = r.hget(f"user:{user_id}", "password").decode('utf-8')
            if check_password_hash(stored_password, password):
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
            user_id = r.incr("user:id")
            try:
                r.set(f"user:id:{username.lower()}", user_id)
                r.set(f"user:username:{user_id}", username)
                r.hset(f"user:{user_id}", mapping={"username": username, "password": hashed_password})
                session['username'] = username
                session['user_id'] = user_id
                if username == 'admin':
                    session['admin'] = True
                return redirect(url_for('index'))
            except redis.exceptions.RedisError as e:
                flash(f'Error: {e}', 'error')
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
            old_username = session['username']
            if r.setnx(f"user:id:{new_username.lower()}", user_id):
                r.rename(f"user:id:{old_username.lower()}", f"user:id:{new_username.lower()}")
                r.set(f"user:username:{user_id}", new_username)
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
                r.set(f"user:password:{user_id}", hashed_password)
                flash('Password updated successfully', 'success')
    user_posts = []
    for key in r.scan_iter(f"post:*:user_id:{user_id}"):
        user_posts.append(json.loads(r.get(key)))
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
            post_id = r.incr("post:id")
            user_id = session['user_id']
            post_data = {
                "id": post_id,
                "user_id": user_id,
                "content": content,
                "upvotes": 0,
                "downvotes": 0
            }
            r.set(f"post:{post_id}", json.dumps(post_data))
            r.set(f"post:{post_id}:user_id:{user_id}", json.dumps(post_data))
            flash('Post created successfully', 'success')
            return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    post_data = r.get(f"post:{post_id}")
    if post_data:
        post = json.loads(post_data)
        if post['user_id'] == user_id:
            r.delete(f"post:{post_id}")
            r.delete(f"post:{post_id}:user_id:{user_id}")
            for key in r.scan_iter(f"comment:{post_id}:*"):
                r.delete(key)
            for key in r.scan_iter(f"vote:{post_id}:*"):
                r.delete(key)
            flash('Post deleted successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/vote/<int:post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    existing_vote = r.hget(f"user:votes:{user_id}", post_id)
    post_data = r.get(f"post:{post_id}")
    if post_data:
        post = json.loads(post_data)
        if existing_vote:
            existing_vote = int(existing_vote)
            if existing_vote == vote:
                r.hdel(f"user:votes:{user_id}", post_id)
                if vote == 1:
                    post['upvotes'] -= 1
                else:
                    post['downvotes'] -= 1
            else:
                r.hset(f"user:votes:{user_id}", post_id, vote)
                if vote == 1:
                    post['upvotes'] += 1
                    post['downvotes'] -= 1
                else:
                    post['upvotes'] -= 1
                    post['downvotes'] += 1
        else:
            r.hset(f"user:votes:{user_id}", post_id, vote)
            if vote == 1:
                post['upvotes'] += 1
            else:
                post['downvotes'] += 1
        r.set(f"post:{post_id}", json.dumps(post))
    return redirect(url_for('index'))

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        comment_content = request.form['comment']
        if comment_content:
            comment_id = r.incr("comment:id")
            user_id = session['user_id']
            comment_data = {
                "id": comment_id,
                "post_id": post_id,
                "user_id": user_id,
                "content": comment_content
            }
            r.set(f"comment:{post_id}:{comment_id}", json.dumps(comment_data))
            flash('Comment added successfully', 'success')
    post_data = r.get(f"post:{post_id}")
    if post_data:
        post = json.loads(post_data)
        post['username'] = get_username(post['user_id'])
        comments = []
        for key in r.scan_iter(f"comment:{post_id}:*"):
            comment = json.loads(r.get(key))
            comment['username'] = get_username(comment['user_id'])
            comments.append(comment)
        user_votes = {int(pid): int(vote) for pid, vote in r.hgetall(f"user:votes:{session['user_id']}").items()}
        return render_template('view_post.html', post=post, comments=comments, user_votes=user_votes, username=session.get('username'))
    return redirect(url_for('index'))

@app.route('/delete_comment/<int:comment_id>')
def delete_comment(comment_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    comment_key = None
    for key in r.scan_iter(f"comment:*:{comment_id}"):
        comment_data = r.get(key)
        if comment_data:
            comment = json.loads(comment_data)
            if comment['user_id'] == user_id:
                comment_key = key
                break
    if comment_key:
        r.delete(comment_key)
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
    comment_id = r.incr("comment:id")
    comment_data = {
        "id": comment_id,
        "post_id": post_id,
        "user_id": user_id,
        "content": content
    }
    r.set(f"comment:{post_id}:{comment_id}", json.dumps(comment_data))
    flash('Comment added successfully', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/admin')
def admin():
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    users = []
    for key in r.scan_iter("user:username:*"):
        user_id = key.split(":")[-1]
        username = r.get(key).decode('utf-8')
        users.append({"id": int(user_id), "username": username})
    posts = []
    for key in r.scan_iter("post:*"):
        posts.append(json.loads(r.get(key)))
    return render_template('admin.html', users=users, posts=posts)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    username = get_username(user_id)
    if username:
        r.delete(f"user:id:{username.lower()}")
        r.delete(f"user:username:{user_id}")
        r.delete(f"user:password:{user_id}")
        r.delete(f"user:votes:{user_id}")
        flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin_delete_post/<int:post_id>')
def admin_delete_post(post_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    post_data = r.get(f"post:{post_id}")
    if post_data:
        post = json.loads(post_data)
        r.delete(f"post:{post_id}")
        r.delete(f"post:{post_id}:user_id:{post['user_id']}")
        for key in r.scan_iter(f"comment:{post_id}:*"):
            r.delete(key)
        for key in r.scan_iter(f"vote:{post_id}:*"):
            r.delete(key)
        flash('Post deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.errorhandler(Exception)
def handle_exception(e):
    print(f"Error: {e}")
    return str(e), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
