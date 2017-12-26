import re
from flask import Flask, render_template, redirect, request, flash, session
from flask_bcrypt import Bcrypt
from mysqlconnection import MySQLConnector

app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'logins')
app.secret_key = 'bleh'

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    query = "SELECT * from users where email = :email LIMIT 1"
    data = {
        'email': request.form['email']
    }
    get_user = mysql.query_db(query, data)
    if get_user:
        session['userid'] = get_user[0]['id']
        session['user_first_name'] = get_user[0]['first_name']
        hashed_password = get_user[0]['password']
        if bcrypt.check_password_hash(hashed_password, request.form['password']):
            session['logged_in'] = True
            flash("Login successful!")
            return redirect('/home')
        else:
            session['logged_in'] = False
            flash("Login failed. Re-enter your credentials or register.")
            return redirect('/')
    else:
        flash("Your email could not be found.")
        return redirect('/')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session['logged_in'] = False
    flash("You have successfuly logged out.")
    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = 0
    if request.method == 'POST':
        first_name = request.form['first_name']
        if not first_name:
            error += 1
            flash("A first name is required.")
        elif not first_name.isalpha():
            error += 1
            flash("Invalid character type, please use letters only.")
        elif len(first_name) < 3:
            error += 1
            flash("First Name must be longer than 2 characters.")

        last_name = request.form['last_name']
        if not last_name:
            error += 1
            flash("A last name is required.")
        elif not last_name.isalpha():
            error += 1
            flash("Invalid character type, please use letters only.")
        elif len(last_name) < 3:
            error += 1
            flash("Last Name must be longer than 2 characters.")
        email = request.form['email']
        if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email):
            error += 1
            flash("Invalid email address.")

        user_password = request.form['user_password']
        confirm_password = request.form['confirm_password']
        if not user_password:
            error += 1
            flash("A Password is required.")
        elif not confirm_password:
            error += 1
            flash("Please confirm your password.")
        if user_password != confirm_password:
            error += 1
            flash("Password does not match. Try again.")
        elif len(user_password) < 8:
            error += 1
            flash("Password must be at least 8 characters long.")
        if error > 0:
            return redirect('/register')
        else:
            pw_hash = bcrypt.generate_password_hash(user_password)
            query = "INSERT INTO users (first_name, last_name, email, password, created_at, \
                                        updated_at) values (:first_name, :last_name, :email, \
                                        :password, now(), now())"
            data = {
                'first_name': first_name, 'last_name': last_name, \
                'email': email, 'password': pw_hash}
            mysql.query_db(query, data)
            session['logged_in'] = True
            return redirect('/home')
    else:
        if request.method == 'GET':

            return render_template('registration.html')

@app.route('/home')
def home():
    if not session['logged_in']:
        flash("Your are not currently logged in, please login or register.")
        return render_template('login.html')
    else:
        return render_template('home.html')
    
app.run(debug=True)