from flask import Flask, render_template, redirect, url_for, jsonify, make_response, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from flask_restful import Resource, Api, reqparse, abort, fields, marshal_with
from flask_httpauth import HTTPBasicAuth
import uuid
import jwt
from functools import wraps
import random, string, json
import pymongo
from pymongo import MongoClient
from dotenv import load_dotenv, find_dotenv
import os
import pprint

load_dotenv(find_dotenv())

password = os.environ.get("MONGODB_PASSWORD")
app = Flask(__name__)
bootstrap = Bootstrap(app)
api = Api(app)
auth = HTTPBasicAuth()
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

connection_string = f"mongodb+srv://masterofsome:{password}@leetapp.y69mx.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"
client = MongoClient(connection_string)
db = client["leetUserDB"]
leetData = db["leetDataDB"]
leetUser = db["leetUserDB"]

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from files import routes
from files.models import Leet
from files.models import User
from files.models import CreateLeet, CreateUser, AuthToken

api.add_resource(CreateUser, "/leet-api/user/<string:user_id>")
api.add_resource(AuthToken, "/leet-api/auth/<string:user_id>")
api.add_resource(CreateLeet, "/leet-api/leet/<string:leet_id>")
