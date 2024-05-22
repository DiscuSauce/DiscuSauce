import sqlite3

def init_db():
    with sqlite3.connect('app.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users
                        (id INTEGER PRIMARY KEY, 
                         username TEXT UNIQUE, 
                         password TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS posts
                        (id INTEGER PRIMARY KEY, 
                         user_id INTEGER, 
                         content TEXT, 
                         upvotes INTEGER DEFAULT 0, 
                         downvotes INTEGER DEFAULT 0, 
                         FOREIGN KEY(user_id) REFERENCES users(id))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS comments
                        (id INTEGER PRIMARY KEY, 
                         post_id INTEGER, 
                         user_id INTEGER, 
                         content TEXT, 
                         FOREIGN KEY(post_id) REFERENCES posts(id), 
                         FOREIGN KEY(user_id) REFERENCES users(id))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS votes
                        (id INTEGER PRIMARY KEY, 
                         post_id INTEGER, 
                         user_id INTEGER, 
                         vote INTEGER, 
                         UNIQUE(post_id, user_id), 
                         FOREIGN KEY(post_id) REFERENCES posts(id), 
                         FOREIGN KEY(user_id) REFERENCES users(id))''')
    print("Database initialized!")

if __name__ == '__main__':
    init_db()
