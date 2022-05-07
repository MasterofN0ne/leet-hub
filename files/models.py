from datetime import datetime, timedelta
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from requests import session
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from files import *
from functools import wraps
from passlib.hash import pbkdf2_sha256
from files import leetUser


class User:
    def start_session(self, user):
        del user['password']
        session['logged_in'] = True
        session['user'] = user
        return jsonify(user), 200

    def signup(self):
        user = {
            "_id": uuid.uuid4().hex,
            "user_public_id": request.form.get('username') + '-' + str(random.randint(0, 1000000)),
            "username": request.form.get('username'),
            "email": request.form.get('mail'),
            "password": request.form.get('password'),
        }
        user['is_active'] = False
        user['password'] = pbkdf2_sha256.encrypt(user['password'])

        if leetUser.find_one({"email": user['email']}):
            return jsonify({"error": "Email address already in use"}), 400

        if leetUser.insert_one(user):
            return self.start_session(user)

        return jsonify({"error": "Signup failed"}), 400

    def signout(self):
        session.clear()
        return redirect('/')

    def login(self):

        user = leetUser.find_one({
            "email": request.form.get('email')
        })

        if user and pbkdf2_sha256.verify(request.form.get('password'), user['password']):
            return self.start_session(user)

        return jsonify({"error": "Invalid login credentials"}), 401


class Leet:
    def add_record():
        leet = {
            "leet_id": str(random.randint(0,1000000)),
            "question": "This was a perfect question",
            "time_spent": "4 minutes",
            "commit_msg": "That was cool",
            "isFailed": "Not yet",
            "commit_date": datetime.utcnow(),
            "qtag": "Linked List",
            "owner_id": "serhat-313131"
        }

        leetData.insert_one(leet)


def check_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message': 'Missing token info'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Invalid token'}), 403

        return func(*args, **kwargs)

    return wrapped


@login_manager.user_loader
def load_user(user_id):
    return leetUser.find_one({"user_public_id": user_id})


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


# Creating and Authenticating user
user_put_args = reqparse.RequestParser()
user_put_args.add_argument("username", type=str, required=True, help="pass a username")
user_put_args.add_argument("email", type=str, required=True, help="pass a email")
user_put_args.add_argument("password", type=str, required=True, help="pass a password")
user_put_args.add_argument("user_public_id", type=str, required=True, help="pass the leet_id")

leet_put_args = reqparse.RequestParser()
leet_put_args.add_argument("leet_id", type=int, required=True, help="Id of the leet")
leet_put_args.add_argument("owner_id", type=str, required=True, help="Owner of the leet")
leet_put_args.add_argument("question", type=str, required=True, help="Enter the question")
leet_put_args.add_argument("time_spent", type=str, required=True, help="Time spent on question")
leet_put_args.add_argument("commit_msg", type=str, required=True, help="Commit message to solution")
leet_put_args.add_argument("isFailed", type=str, required=True, help="Failed ot not")
leet_put_args.add_argument("qtag", type=str, required=True, help="Tag of the question")
leet_put_args.add_argument("date", type=str, help="date of commit")

user_resource_fields = {
    'username': fields.String,
    'email': fields.String,
    'password': fields.String,
    'user_public_id': fields.String,
}

leet_resource_fields = {
    'leet_id': fields.Integer,
    'owner_id': fields.String,
    'question': fields.String,
    'time_spent': fields.String,
    'commit_msg': fields.String,
    'isFailed': fields.String,
    'date': fields.DateTime
}


class AuthToken(Resource):
    @marshal_with(user_resource_fields)
    def get(self, user_id):
        user = leetUser.find_one({'user_public_id': user_id})
        token = jwt.encode(
                {
                    'user': user_id,
                    'exp': datetime.utcnow() + timedelta(hours=24)
                },
                app.config['SECRET_KEY'])
        return jsonify({'token': token})
    


class CreateUser(Resource):
    @marshal_with(user_resource_fields)
    def get(self, user_id):
        if not session.get('logged_in'):
            abort(404, message="User not logged in..")

        result = leetUser.find_one({'user_public_id': user_id})
        if not result:
            abort(404, message="Username not found")

        return jsonify(result), 201

    
    def put(self, user_id):
        """
        username
        email
        password
        leets
        """
        if not session.get('logged_in'):
            abort(404, message="User not logged in..")

        args = user_put_args.parse_args()
        result = leetUser.find_one({'user_public_id': user_id})
        if result:
            abort(409, message="User already exist")

        user = {
            'username': args['username'],
            'email': args['email'],
            'password': args['password'],
            'user_public_id': args['user_public_id']
        }

        leetUser.insert_one(user)

    def delete(self, user_id):
        if not session.get('logged_in'):
            abort(404, message="User not logged in..")

        delops = leetUser.delete_one({'user_public_id': user_id})
        if not delops:
            abort(404, message="Delete operation can't be completed")
        


class CreateLeet(Resource):
    @marshal_with(leet_resource_fields)

    def get(self, leet_id):
        if not session.get('logged_in'):
            abort(404, message="User not logged in..")

        result = leetData.find_one({'leet_id': leet_id})
        if not result:
            abort(409, message="Leet id not found")
        return jsonify(result)

    def put(self, leet_id):
        """
        owner_id
        leet_id
        question
        time spent
        commit message
        question tag
        isFailed
        date
        """
        if not session.get('logged_in'):
            abort(404, message="User not logged in..")

        args = leet_put_args.parse_args()
        result = leetData.find_one({'leet_id': leet_id})
        if result:
            abort(409, message="Leet id already in use")

        leet = {
            'leet_id': args["leet_id"],
            'question': args["question"],
            'time_spent': args["time_spent"],
            'commit_msg': args["commit_msg"],
            'isFailed': args["isFailed"],
            'qtag': args["q_tag"],
            'owner_id': args['owner_id']
        }
        
        return jsonify(leet), 201


    def delete(self, leet_id):
        if not session.get('logged_in'):
            abort(404, message="User not logged in..")

        delops = leetData.delete_one({'leet_id': leet_id})

        if not delops:
            abort(404, message="Delete operation can't be completed")
        
