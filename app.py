from flask import Flask, render_template, request, redirect, url_for, session, g
from flask_mysqldb import MySQL
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Установите ваш ключ

# Настройки для подключения к базе данных MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'Admin'
app.config['MYSQL_PASSWORD'] = 'Adminpassword1'
app.config['MYSQL_DB'] = 'forum'

mysql = MySQL(app)

def xor_encrypt(text, key):
    encrypted_text = ""
    for char in text:
        encrypted_text += chr(ord(char) ^ key)
    return encrypted_text

def xor_decrypt(encrypted_text, key):
    decrypted_text = ""
    for char in encrypted_text:
        decrypted_text += chr(ord(char) ^ key)
    return decrypted_text

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = mysql.connection
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Маршрут для удаления конкретного сообщения
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    cursor = mysql.connection.cursor()
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    mysql.connection.commit()
    cursor.close()
    return redirect(url_for('delete_user_redirect'))

# Маршрут для удаления конкретного сообщения
@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    cursor = mysql.connection.cursor()
    cursor.execute('DELETE FROM messages WHERE id = %s', (message_id,))
    mysql.connection.commit()
    cursor.close()
    return redirect(url_for('messages'))

# Маршрут для удаления всех сообщений
@app.route('/delete_all_messages', methods=['POST'])
def delete_all_messages():
    cursor = mysql.connection.cursor()
    cursor.execute('DELETE FROM messages')
    mysql.connection.commit()
    cursor.close()
    return redirect(url_for('messages'))

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        #if request.form['username'] != "Admin":
        #    encryption_key = 42
        #    password = xor_encrypt(password, encryption_key)
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
        user = cursor.fetchone()
        cursor.close()
        if user:
            if user[3] == 1:  # Проверка значения поля can_login
                session['username'] = username
                return redirect(url_for('messages'))
            else:
                return render_template('login.html', error='Ваш аккаунт еще не подтвержден')
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        message = request.form['message']
        username = session['username']
        cursor = mysql.connection.cursor()
        cursor.execute('INSERT INTO messages (username, message, created_at, datetime) VALUES (%s, %s, %s, %s)', (username, message, str(datetime.datetime.now()), str(datetime.datetime.now())))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for('messages'))

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM messages ORDER BY id DESC')
    messages = cursor.fetchall()
    cursor.close()
    return render_template('messages.html', messages=messages, username=session['username'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        encryption_key = 42
        #password = xor_encrypt(password, encryption_key)
        db = get_db()
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username=%s', (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            return render_template('register.html', error='Username already exists')
        else:
            cursor.execute('INSERT INTO users (username, password, can_login) VALUES (%s, %s, %s)', (username, password, 0))
            mysql.connection.commit()
            cursor.close()
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    if request.method == 'POST':
        if 'username' in session and session['username'] == 'Admin':
            if session.get('password') != 'dsa':
                cursor = mysql.connection.cursor()
                cursor.execute('SELECT * FROM users')
                users = cursor.fetchall()
                for user in users:
                    username = user[1]
                    can_login = request.form.get(username)
                    if can_login:
                        can_login = 1
                    else:
                        can_login = 0
                    cursor.execute('UPDATE users SET can_login=%s WHERE username=%s', (can_login, username))
                mysql.connection.commit()
                cursor.close()
                return redirect(url_for('admin_panel'))
            else:
                return "Access denied. Invalid password."
        else:
            return redirect(url_for('login'))
    else:
        if 'username' in session and session['username'] == 'Admin':
            # Проверяем, что пользователь с именем 'Admin' вошел в систему
            cursor = mysql.connection.cursor()
            cursor.execute('SELECT * FROM users')
            users = cursor.fetchall()
            cursor.close()
            return render_template('admin_panel.html', users=users)
        else:
            return redirect(url_for('login'))

@app.route('/delete_user_redirect', methods=['GET', 'POST'])
def delete_user_redirect():
    if request.method == 'POST':
        if 'username' in session and session['username'] == 'Admin':
            if session.get('password') != 'dsa':
                cursor = mysql.connection.cursor()
                cursor.execute('SELECT * FROM users')
                users = cursor.fetchall()
                for user in users:
                    username = user[1]
                    can_login = request.form.get(username)
                    if can_login:
                        can_login = 1
                    else:
                        can_login = 0
                    cursor.execute('UPDATE users SET can_login=%s WHERE username=%s', (can_login, username))
                mysql.connection.commit()
                cursor.close()
                return redirect(url_for('delete_user_redirect'))
            else:
                return "Access denied. Invalid password."
        else:
            return redirect(url_for('login'))
    else:
        if 'username' in session and session['username'] == 'Admin':
            # Проверяем, что пользователь с именем 'Admin' вошел в систему
            cursor = mysql.connection.cursor()
            cursor.execute('SELECT * FROM users')
            users = cursor.fetchall()
            cursor.close()
            return render_template('delete_user_redirect.html', users=users)
        else:
            return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)