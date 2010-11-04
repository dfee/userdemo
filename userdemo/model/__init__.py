from mongoengine import *
import datetime

connect('userdemo_dev')

class User(Document):
    username = StringField(max_length=50, required=True, unique=True)
    email = StringField(max_length=50, required=True, unique=True)
    password = StringField(required=True)
    salt = StringField(required=True)
    date_created = DateTimeField(default=datetime.datetime.utcnow)
    first_name = StringField(required=True)
    last_name = StringField(required=True)
