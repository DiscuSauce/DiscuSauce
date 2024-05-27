import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin
import html
from pymongo import MongoClient
from bson.objectid import ObjectId

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', '$E5Q!8snLRG!8^$Old*a#A1RMhgaUp@r0dv2lOb5ecGrS&0Fci')

# MongoDB configuration
MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://aarondiss:wiDZEYFdCevTXtyA@diss.la46vs4.mongodb.net/?retryWrites=true&w=majority&appName=diss')
client = MongoClient(MONGO_URI)
db = client['your_database_name']  # Replace with your database name

def get_db():
    if 'db' not in g:
        g.db = db
    return g.db

@app.before_request
def before_request():
    g.db = get_db()

@app.teardown_request
def teardown_request(exception):
    g.pop('db', None)

def sanitize_input(input):
    return html.escape(input)

def get_user_id(username):
    user = g.db.users.find_one({'username': username})
    return str(user['_id']) if user else None

def get_user(user_id):
    user = g.db.users.find_one({'_id': ObjectId(user_id)})
    return {'id': str(user['_id']), 'username': user['username'], 'password': user['password']} if user else None

def create_user(username, password):
    hashed_password = generate_password_hash(password)
    result = g.db.users.insert_one({'username': username, 'password': hashed_password})
    return str(result.inserted_id)

def create_post(user_id, content):
    result = g.db.posts.insert_one({'user_id': ObjectId(user_id), 'content': content, 'upvotes': 0, 'downvotes': 0})
    return str(result.inserted_id)

def flash_message(category, message):
    flash(message, category)

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/')
def index():
    if 'username' in session:
        posts = list(g.db.posts.aggregate([
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'user_id',
                    'foreignField': '_id',
                    'as': 'user'
                }
            },
            {
                '$unwind': '$user'
            },
            {
                '$sort': {'upvotes': -1, 'downvotes': 1}
            }
        ]))
        user_votes = {vote['post_id']: vote['vote'] for vote in g.db.votes.find({'user_id': ObjectId(session['user_id'])})}
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
                g.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'username': new_username}})
                session['username'] = new_username
                flash_message('success', 'Username updated successfully')
        if new_password:
            if len(new_password) < 8:
                flash_message('error', 'Password must be at least 8 characters long')
            elif new_password != confirm_password:
                flash_message('error', 'Passwords do not match')
            else:
                hashed_password = generate_password_hash(new_password)
                g.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'password': hashed_password}})
                flash_message('success', 'Password updated successfully')
    user = get_user(user_id)
    return render_template('profile.html', username=user['username'])

@app.route('/create', methods=['GET', 'POST'])
def create():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form['content']
        content = sanitize_input(content)
        create_post(session['user_id'], content)
        return redirect(url_for('index'))
    return render_template('create.html')

@app.route('/upvote/<string:post_id>', methods=['POST'])
def upvote(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    vote = g.db.votes.find_one({'post_id': ObjectId(post_id), 'user_id': ObjectId(user_id)})
    if vote:
        if vote['vote'] == 1:
            g.db.votes.delete_one({'_id': vote['_id']})
            g.db.posts.update_one({'_id': ObjectId(post_id)}, {'$inc': {'upvotes': -1}})
        else:
            g.db.votes.update_one({'_id': vote['_id']}, {'$set': {'vote': 1}})
            g.db.posts.update_one({'_id': ObjectId(post_id)}, {'$inc': {'upvotes': 1, 'downvotes': -1}})
    else:
        g.db.votes.insert_one({'post_id': ObjectId(post_id), 'user_id': ObjectId(user_id), 'vote': 1})
        g.db.posts.update_one({'_id': ObjectId(post_id)}, {'$inc': {'upvotes': 1}})
    return redirect(url_for('index'))

@app.route('/downvote/<string:post_id>', methods=['POST'])
def downvote(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    vote = g.db.votes.find_one({'post_id': ObjectId(post_id), 'user_id': ObjectId(user_id)})
    if vote:
        if vote['vote'] == -1:
            g.db.votes.delete_one({'_id': vote['_id']})
            g.db.posts.update_one({'_id': ObjectId(post_id)}, {'$inc': {'downvotes': -1}})
        else:
            g.db.votes.update_one({'_id': vote['_id']}, {'$set': {'vote': -1}})
            g.db.posts.update_one({'_id': ObjectId(post_id)}, {'$inc': {'upvotes': -1, 'downvotes': 1}})
    else:
        g.db.votes.insert_one({'post_id': ObjectId(post_id), 'user_id': ObjectId(user_id), 'vote': -1})
        g.db.posts.update_one({'_id': ObjectId(post_id)}, {'$inc': {'downvotes': 1}})
    return redirect(url_for('index'))

@app.route('/delete/<string:post_id>', methods=['POST'])
def delete(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    g.db.comments.delete_many({'post_id': ObjectId(post_id)})
    g.db.votes.delete_many({'post_id': ObjectId(post_id)})
    g.db.posts.delete_one({'_id': ObjectId(post_id)})
    return redirect(url_for('index'))

@app.route('/comment/<string:post_id>', methods=['POST'])
def comment(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    content = request.form['content']
    content = sanitize_input(content)
    g.db.comments.insert_one({'post_id': ObjectId(post_id), 'user_id': ObjectId(session['user_id']), 'content': content})
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
