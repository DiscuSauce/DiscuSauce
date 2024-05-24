import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_session import Session
from flask_env import MetaFlaskEnv
import re

app = Flask(__name__)
app.config.from_object(os.environ['APP_SETTINGS'])
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
sess = Session(app)
meta = MetaFlaskEnv()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def __init__(self, username, password, is_admin=False):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.is_admin = is_admin

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='post', lazy='dynamic')
    votes = db.relationship('Vote', backref='post', lazy='dynamic')

    def __init__(self, user_id, content):
        self.user_id = user_id
        self.content = content

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)

    def __init__(self, post_id, user_id, content):
        self.post_id = post_id
        self.user_id = user_id
        self.content = content

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vote = db.Column(db.Integer, nullable=False)

    def __init__(self, post_id, user_id, vote):
        self.post_id = post_id
        self.user_id = user_id
        self.vote = vote

@app.before_request
def load_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            session['username'] = user.username
            session['is_admin'] = user.is_admin

def is_safe_url(target):
    ref_url = request.host_url
    test_url = urljoin(request.host_url, target)
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/')
def index():
    if 'username' in session:
        posts = Post.query.order_by(Post.upvotes - Post.downvotes.desc()).all()
        user_votes = {v.post_id: v.vote for v in Vote.query.filter_by(user_id=session['user_id']).all()}
        return render_template('index.html', username=session['username'], posts=posts, user_votes=user_votes)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
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
        elif User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        else:
            user = User(username, password)
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        new_username = request.form['new_username']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_username and len(new_username) < 3:
            flash('Username must be at least 3 characters long', 'error')
        elif new_username and User.query.filter_by(username=new_username).first():
            flash('Username already exists', 'error')
        else:
            user.username = new_username or user.username
        if new_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'error')
            elif new_password != confirm_password:
                flash('Passwords do not match', 'error')
            else:
                user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                flash('Password updated successfully', 'success')
        if new_username or new_password:
            db.session.commit()
    user_posts = user.posts.all()
    return render_template('profile.html', posts=user_posts)

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form['content']
        if not content:
            flash('Post content cannot be empty', 'error')
        elif len(content.split()) > 64:
            flash('Post content exceeds 64 words limit', 'error')
        else:
            post = Post(session['user_id'], content)
            db.session.add(post)
            db.session.commit()
            flash('Post created successfully', 'success')
            return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/delete_post/int:post_id', methods=['POST'])
@csrf.exempt
def delete_post(post_id):
if 'user_id' not in session:
return redirect(url_for('login'))
post = Post.query.get_or_404(post_id)
if post.author.id == session['user_id'] or session['is_admin']:
comments = Comment.query.filter_by(post_id=post_id).all()
for comment in comments:
db.session.delete(comment)
votes = Vote.query.filter_by(post_id=post_id).all()
for vote in votes:
db.session.delete(vote)
db.session.delete(post)
db.session.commit()
flash('Post deleted successfully', 'success')
else:
flash('You are not authorized to delete this post', 'error')
return redirect(url_for('profile'))
@app.route('/vote/int:post_id/int:vote')
def vote(post_id, vote):
if 'user_id' not in session:
return redirect(url_for('login'))
post = Post.query.get_or_404(post_id)
user_vote = Vote.query.filter_by(post_id=post_id, user_id=session['user_id']).first()
if user_vote:
if user_vote.vote == vote:
db.session.delete(user_vote)
if vote == 1:
post.upvotes -= 1
else:
post.downvotes -= 1
else:
user_vote.vote = vote
if vote == 1:
post.upvotes += 1
post.downvotes -= 1
else:
post.upvotes -= 1
post.downvotes += 1
else:
new_vote = Vote(post_id, session['user_id'], vote)
db.session.add(new_vote)
if vote == 1:
post.upvotes += 1
else:
post.downvotes += 1
db.session.commit()
return redirect(url_for('index'))
@app.route('/view_post/int:post_id')
def view_post(post_id):
post = Post.query.get_or_404(post_id)
comments = post.comments.all()
return render_template('view_post.html', post=post, comments=comments)
@app.route('/logout')
def logout():
session.pop('user_id', None)
session.pop('username', None)
session.pop('is_admin', None)
return redirect(url_for('login'))
@app.route('/create_comment/int:post_id', methods=['POST'])
@csrf.exempt
def create_comment(post_id):
if 'user_id' not in session:
return redirect(url_for('login'))
content = request.form['comment']
if not content:
flash('Comment cannot be empty', 'error')
else:
comment = Comment(post_id, session['user_id'], content)
db.session.add(comment)
db.session.commit()
flash('Comment added successfully', 'success')
return redirect(url_for('view_post', post_id=post_id))
@app.route('/admin')
def admin():
if 'user_id' not in session or not session['is_admin']:
return redirect(url_for('login'))
users = User.query.all()
posts = Post.query.all()
return render_template('admin.html', users=users, posts=posts)
@app.route('/delete_user/int:user_id', methods=['POST'])
@csrf.exempt
def delete_user(user_id):
if 'user_id' not in session or not session['is_admin']:
return redirect(url_for('login'))
user = User.query.get_or_404(user_id)
posts = Post.query.filter_by(user_id=user_id).all()
for post in posts:
comments = Comment.query.filter_by(post_id=post.id).all()
for comment in comments:
db.session.delete(comment)
votes = Vote.query.filter_by(post_id=post.id).all()
for vote in votes:
db.session.delete(vote)
db.session.delete(post)
comments = Comment.query.filter_by(user_id=user_id).all()
for comment in comments:
db.session.delete(comment)
votes = Vote.query.filter_by(user_id=user_id).all()
for vote in votes:
db.session.delete(vote)
db.session.delete(user)
db.session.commit()
flash('User deleted successfully', 'success')
return redirect(url_for('admin'))
@app.route('/admin_delete_post/int:post_id', methods=['POST'])
@csrf.exempt
def admin_delete_post(post_id):
if 'user_id' not in session or not session['is_admin']:
return redirect(url_for('login'))
post = Post.query.get_or_404(post_id)
comments = Comment.query.filter_by(post_id=post_id).all()
for comment in comments:
db.session.delete(comment)
votes = Vote.query.filter_by(post_id=post_id).all()
for vote in votes:
db.session.delete(vote)
db.session.delete(post)
db.session.commit()
flash('Post deleted successfully', 'success')
return redirect(url_for('admin'))
if name == 'main':
port = int(os.environ.get('PORT', 5000))
app.run(host='0.0.0.0', port=port, debug=True)
