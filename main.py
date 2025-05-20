from flask import Flask, request, session, redirect, url_for
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # 用於加密 session

# MongoDB 連接
client = MongoClient("mongodb://localhost:27017/")  # 替換為你的 MongoDB 連接字符串
db = client["mydatabase"]  # 替換為你的數據庫名稱

# 使用 before_request 並加條件模擬 before_first_request
initialized = False


@app.before_request
def initialize_data():
    global initialized
    if not initialized:
        # 插入用戶數據
        db.users.insert_one({
            "username": "bob",
            "password_hash": generate_password_hash("password1"),
            "role": "user",
            "attributes": {"team": "PM", "location": "Taichung"}
        })

        # 插入角色數據
        db.roles.insert_one({
            "name": "user",
            "permissions": ["read_users"]
        })

        initialized = True


# 登入頁面
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 從 MongoDB 查詢使用者資料
        user = db.users.find_one({"username": username})

        if user and check_password_hash(user['password_hash'], password):
            # 登入成功
            return f"Welcome, {username}!", 200
        else:
            # 登入失敗
            return "Invalid username or password", 401

    return '''
        <form method="post">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Login">
        </form>
    '''

# 登出頁面
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for(''))

# 儀表板頁面
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f"Welcome, {session['username']}! <a href='/logout'>Logout</a>"
    return redirect(url_for(''))

if __name__ == '__main__':
    app.run()