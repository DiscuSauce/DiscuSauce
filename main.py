from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import redis
import uuid

app = Flask(__name__)
app.secret_key = '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci'

r = redis.Redis(
  host='redis-16989.c11.us-east-1-2.ec2.redns.redis-cloud.com',
  port=16989,
  password='uo9iVA7KLndbJRy3IK3NcjLWL5eYqcus'
)

def get_user_id(username):
    return r.hget("users", username)

@app.route('/')
def index():
    if 'username' in session:
        posts = []
        post_ids = r.lrange('posts', 0, -1)
        for post_id in post_ids:
            post = r.hgetall(f'post:{post_id}')
            post['id'] = post_id
            post['username'] = r.hget(f'user:{post["user_id"]}', 'username')
            posts.append(post)
        user_votes = r.hgetall(f'votes:{session["user_id"]}')
        user_votes = {int(k): int(v) for k, v in user_votes.items()}
        return render_template('index.html', username=session['username'], posts=posts, user_votes=user_votes)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_id = get_user_id(username)
        if user_id:
            user = r.hgetall(f'user:{user_id}')
            if check_password_hash(user['password'], password):
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
            user_id = str(uuid.uuid4())
            if r.hsetnx('users', username, user_id):
                r.hmset(f'user:{user_id}', {'username': username, 'password': hashed_password})
                session['username'] = username
                session['user_id'] = user_id
                if username == 'admin':
                    session['admin'] = True
                return redirect(url_for('index'))
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
            if r.hsetnx('users', new_username, user_id):
                old_username = session['username']
                r.hdel('users', old_username)
                r.hset('users', new_username, user_id)
                r.hset(f'user:{user_id}', 'username', new_username)
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
                r.hset(f'user:{user_id}', 'password', hashed_password)
                flash('Password updated successfully', 'success')
    user_posts = [r.hgetall(f'post:{post_id}') for post_id in r.lrange(f'user_posts:{user_id}', 0, -1)]
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
            post_id = str(uuid.uuid4())
            r.hmset(f'post:{post_id}', {'user_id': user_id, 'content': content, 'upvotes': 0, 'downvotes': 0})
            r.rpush('posts', post_id)
            r.rpush(f'user_posts:{user_id}', post_id)
            flash('Post created successfully', 'success')
            return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/delete_post/<post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    post = r.hgetall(f'post:{post_id}')
    if post and post['user_id'] == user_id:
        r.lrem('posts', 0, post_id)
        r.lrem(f'user_posts:{user_id}', 0, post_id)
        r.delete(f'post:{post_id}')
        r.delete(f'post_comments:{post_id}')
        r.delete(f'post_votes:{post_id}')
        flash('Post deleted successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/vote/<post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    post_key = f'post:{post_id}'
    vote_key = f'votes:{user_id}'
    existing_vote = r.hget(vote_key, post_id)
    if existing_vote is not None:
        existing_vote = int(existing_vote)
        if existing_vote == vote:
            r.hdel(vote_key, post_id)
            r.hincrby(post_key, 'upvotes' if vote == 1 else 'downvotes', -1)
        else:
            r.hset(vote_key, post_id, vote)
            r.hincrby(post_key, 'upvotes', 1 if vote == 1 else -1)
            r.hincrby(post_key, 'downvotes', -1 if vote == 1 else 1)
    else:
        r.hset(vote_key, post_id, vote)
        r.hincrby(post_key, 'upvotes' if vote == 1 else 'downvotes', 1)
    return redirect(url_for('index'))

@app.route('/post/<post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        comment_content = request.form['comment']
        if comment_content:
            user_id = session['user_id']
            comment_id = str(uuid.uuid4())
            r.hmset(f'comment:{comment_id}', {'post_id': post_id, 'user_id': user_id, 'content': comment_content})
            r.rpush(f'post_comments:{post_id}', comment_id)
            flash('Comment added successfully', 'success')
    post = r.hgetall(f'post:{post_id}')
    post['username'] = r.hget(f'user:{post["user_id"]}', 'username')
    comments = [r.hgetall(f'comment:{comment_id}') for comment_id in r.lrange(f'post_comments:{post_id}', 0, -1)]
    for comment in comments:
        comment['username'] = r.hget(f'user:{comment["user_id"]}', 'username')
    user_votes = r.hgetall(f'votes:{session["user_id"]}')
    user_votes = {int(k): int(v) for k, v in user_votes.items()}
    return render_template('view_post.html', post=post, comments=comments, user_votes=user_votes, username=session.get('username'))

@app.route('/delete_comment/<comment_id>')
def delete_comment(comment_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    comment = r.hgetall(f'comment:{comment_id}')
    if comment and comment['user_id'] == user_id:
        r.lrem(f'post_comments:{comment["post_id"]}', 0, comment_id)
        r.delete(f'comment:{comment_id}')
        flash('Comment deleted successfully', 'success')
    return redirect(url_for('view_post', post_id=comment['post_id']))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('admin', None)
    return redirect(url_for('login'))

@app.route('/create_comment/<post_id>', methods=['POST'])
def create_comment(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    content = request.form['comment']
    user_id = session['user_id']
    comment_id = str(uuid.uuid4())
    r.hmset(f'comment:{comment_id}', {'post_id': post_id, 'user_id': user_id, 'content': content})
    r.rpush(f'post_comments:{post_id}', comment_id)
    flash('Comment added successfully', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/admin')
def admin():
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    users = r.hkeys('users')
    user_data = [(r.hget(f'user:{user_id}', 'username'), user_id) for user_id in users]
    post_ids = r.lrange('posts', 0, -1)
    posts = [(r.hget(f'post:{post_id}', 'content'), post_id) for post_id in post_ids]
    return render_template('admin.html', users=user_data, posts=posts)

@app.route('/delete_user/<user_id>')
def delete_user(user_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    username = r.hget(f'user:{user_id}', 'username')
    r.hdel('users', username)
    r.delete(f'user:{user_id}')
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin_delete_post/<post_id>')
def admin_delete_post(post_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    r.lrem('posts', 0, post_id)
    r.delete(f'post:{post_id}')
    r.delete(f'post_comments:{post_id}')
    r.delete(f'post_votes:{post_id}')
    flash('Post deleted successfully', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)
