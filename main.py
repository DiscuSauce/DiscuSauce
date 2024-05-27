import redis
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci'

r = redis.Redis(
  host='redis-16989.c11.us-east-1-2.ec2.redns.redis-cloud.com',
  port=16989,
  password='uo9iVA7KLndbJRy3IK3NcjLWL5eYqcus'
)

def get_next_id(key):
    return r.incr(key)

def get_user_by_username(username):
    user_data = r.get(f"user:{username}")
    if user_data:
        return json.loads(user_data)
    return None

def get_user_by_id(user_id):
    user_data = r.get(f"user_id:{user_id}")
    if user_data:
        return json.loads(user_data)
    return None

def save_user(user):
    r.set(f"user:{user['username']}", json.dumps(user))
    r.set(f"user_id:{user['id']}", json.dumps(user))

def get_post_by_id(post_id):
    post_data = r.get(f"post:{post_id}")
    if post_data:
        return json.loads(post_data)
    return None

def save_post(post):
    r.set(f"post:{post['id']}", json.dumps(post))
    r.lpush("posts", post['id'])

def get_all_posts():
    post_ids = r.lrange("posts", 0, -1)
    posts = []
    for post_id in post_ids:
        post = get_post_by_id(int(post_id))
        if post:
            posts.append(post)
    return posts

def get_comments_by_post_id(post_id):
    comment_ids = r.lrange(f"post_comments:{post_id}", 0, -1)
    comments = []
    for comment_id in comment_ids:
        comment_data = r.get(f"comment:{comment_id}")
        if comment_data:
            comments.append(json.loads(comment_data))
    return comments

def save_comment(comment):
    r.set(f"comment:{comment['id']}", json.dumps(comment))
    r.lpush(f"post_comments:{comment['post_id']}", comment['id'])

@app.route('/')
def index():
    if 'username' in session:
        posts = get_all_posts()
        return render_template('index.html', username=session['username'], posts=posts)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user_by_username(username)
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
            user_id = get_next_id("user_id")
            user = {
                'id': user_id,
                'username': username,
                'password': hashed_password
            }
            if get_user_by_username(username) is None:
                save_user(user)
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
            user = get_user_by_id(user_id)
            if user:
                user['username'] = new_username
                save_user(user)
                session['username'] = new_username
                flash('Username updated successfully', 'success')
        if new_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'error')
            elif new_password != confirm_password:
                flash('Passwords do not match', 'error')
            else:
                hashed_password = generate_password_hash(new_password)
                user = get_user_by_id(user_id)
                if user:
                    user['password'] = hashed_password
                    save_user(user)
                    flash('Password updated successfully', 'success')
    user_posts = [get_post_by_id(int(post_id)) for post_id in r.lrange(f"user_posts:{user_id}", 0, -1)]
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
            post_id = get_next_id("post_id")
            post = {
                'id': post_id,
                'user_id': user_id,
                'content': content,
                'upvotes': 0,
                'downvotes': 0
            }
            save_post(post)
            r.lpush(f"user_posts:{user_id}", post_id)
            flash('Post created successfully', 'success')
            return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    post = get_post_by_id(post_id)
    if post and post['user_id'] == user_id:
        r.delete(f"post:{post_id}")
        r.lrem("posts", 0, post_id)
        r.delete(f"user_posts:{user_id}")
        r.delete(f"post_comments:{post_id}")
        flash('Post deleted successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/vote/<int:post_id>/<int:vote>')
def vote(post_id, vote):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    post = get_post_by_id(post_id)
    if not post:
        return redirect(url_for('index'))
    
    vote_key = f"vote:{post_id}:{user_id}"
    current_vote = r.get(vote_key)
    
    if current_vote is None:
        r.set(vote_key, vote)
        if vote == 1:
            post['upvotes'] += 1
        else:
            post['downvotes'] += 1
    else:
        current_vote = int(current_vote)
        if current_vote == vote:
            r.delete(vote_key)
            if vote == 1:
                post['upvotes'] -= 1
            else:
                post['downvotes'] -= 1
        else:
            r.set(vote_key, vote)
            if vote == 1:
                post['upvotes'] += 1
                post['downvotes'] -= 1
            else:
                post['upvotes'] -= 1
                post['downvotes'] += 1
    
    save_post(post)
    return redirect(url_for('index'))

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        comment_content = request.form['comment']
        if comment_content:
            user_id = session['user_id']
            comment_id = get_next_id("comment_id")
            comment = {
                'id': comment_id,
                'post_id': post_id,
                'user_id': user_id,
                'content': comment_content
            }
            save_comment(comment)
            flash('Comment added successfully', 'success')
    post = get_post_by_id(post_id)
    comments = get_comments_by_post_id(post_id)
    return render_template('view_post.html', post=post, comments=comments)

@app.route('/delete_comment/<int:comment_id>')
def delete_comment(comment_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    comment_data = r.get(f"comment:{comment_id}")
    if comment_data:
        comment = json.loads(comment_data)
        if comment['user_id'] == user_id:
            r.delete(f"comment:{comment_id}")
            r.lrem(f"post_comments:{comment['post_id']}", 0, comment_id)
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
    comment_id = get_next_id("comment_id")
    comment = {
        'id': comment_id,
        'post_id': post_id,
        'user_id': user_id,
        'content': content
    }
    save_comment(comment)
    flash('Comment added successfully', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/admin')
def admin():
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    user_ids = r.keys("user:*")
    users = [json.loads(r.get(user_id)) for user_id in user_ids if b"user_id:" not in user_id]
    post_ids = r.lrange("posts", 0, -1)
    posts = [get_post_by_id(int(post_id)) for post_id in post_ids]
    return render_template('admin.html', users=users, posts=posts)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    user = get_user_by_id(user_id)
    if user:
        r.delete(f"user:{user['username']}")
        r.delete(f"user_id:{user_id}")
        flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin_delete_post/<int:post_id>')
def admin_delete_post(post_id):
    if 'username' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    post = get_post_by_id(post_id)
    if post:
        r.delete(f"post:{post_id}")
        r.lrem("posts", 0, post_id)
        flash('Post deleted successfully', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)
