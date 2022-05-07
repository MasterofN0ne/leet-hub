from crypt import methods
from flask import Flask, render_template, redirect, url_for, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from datetime import datetime, timedelta
from flask_restful import Resource, Api, reqparse, abort, fields, marshal_with
from files import *
from files.models import User, Leet, LoginForm, RegisterForm
from passlib.hash import pbkdf2_sha256




def start_session(user):
    del user['password']
    session['logged_in'] = True
    session['user'] = user
    
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')
    return wrap

def check_for_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message': 'Missing token'}), 403
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Invalid token'}), 403

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = leetUser.find_one({
            'username': request.form.get('username'),
        })

        if user and pbkdf2_sha256.verify(request.form.get('password'), user['password']):
            make_active = {"$set": {"is_active": True}}
            leetUser.update_one({"username": user["username"]}, make_active)
            start_session(user)
            return redirect(f"dashboard/{user['user_public_id']}")

        return '<h1>Invalid username or password</h1>'
    
    return render_template('login.html', form=form)
    

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = {
            "_id": uuid.uuid4().hex,
            "user_public_id": request.form.get('username') + '-' + str(random.randint(0, 1000000)),
            "username": request.form.get('username'),
            "email": request.form.get('email'),
            "password": request.form.get('password'),
        }

        new_user['password'] = pbkdf2_sha256.encrypt(new_user['password'])
        new_user['is_active'] = False
        leetUser.insert_one(new_user)
        return f"<h1>New user has been created with the public id: {new_user['user_public_id']}</h1>"
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard/<string:user_id>')
@login_required
def dashboard(user_id):
    user = leetUser.find_one({"user_public_id": user_id})
    if user["cli_user"]:
        if jwt.decode(user['token'], app.config["SECRET_KEY"]):
            items = leetData.find({"owner_id": user_id})
            return render_template('dashboard.html', items=items)
        else:
            return jsonify({'message': 'Not authorized user'})
    else:
        items = leetData.find({"owner_id": user_id})
        return render_template('dashboard.html', items=items)

@app.route('/api-login/<string:user_id>', methods=['GET','POST'])
def api_login(user_id):
    user = leetUser.find_one({'user_public_id': user_id})
    if user:
        token = jwt.encode(
                {
                    'user': user_id,
                    'exp': datetime.utcnow() + timedelta(hours=24)
                },
                app.config['SECRET_KEY'])
        return jsonify({'token': token})
    
    return jsonify({'message': 'User not logged in'})


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
