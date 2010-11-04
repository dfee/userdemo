import logging
import formencode, formencode.htmlfill
from pylons import request, response, session, tmpl_context as c, url
from pylons.controllers.util import abort, redirect
from userdemo.lib.base import BaseController, render
from userdemo.model import User
import hashlib
import random

log = logging.getLogger(__name__)

class InvalidUser(Exception):
    pass

def hash_password(password, salt):
    m = hashlib.sha256()
    m.update(password)
    m.update(salt)
    return m.hexdigest()

def gen_hash_password(password):
    import random
    letters = 'abcdefghijklmnopqrstuvwxyz0123456789'
    p = ''
    random.seed()
    for x in range(32):
        p += letters[random.randint(0, len(letters)-1)]
    return hash_password(password, p), p

def authenticate_user(username, password):
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist, e:
        raise InvalidUser('bad username')
    else:
        # check pw
        if not hash_password(password, user.salt) == user.password:
            raise InvalidUser('bad password')
    
        return user

def user_exists(username):
    try:
        result = User.objects.get(username=username)
    except User.DoesNotExist, e:
        return False
    return True

class UsernameValidator(formencode.validators.String):
    def validate_python(self, value, state):
        if user_exists(value):
            raise formencode.Invalid('Username already taken', value, state)

class RegisterForm(formencode.Schema):
    username = UsernameValidator(not_empty=True)
    password = formencode.validators.String(not_empty=True)
    email = formencode.validators.String(not_empty=True)
    first_name = formencode.validators.String(not_empty=True)
    last_name = formencode.validators.String(not_empty=True)

class LoginForm(formencode.Schema):
    username = formencode.validators.String(not_empty=True)
    password = formencode.validators.String(not_empty=True)


class AuthController(BaseController):
    def login(self):
        return render('login.html')
    
    def login_post(self):
        try:
            form_result = LoginForm().to_python(request.POST)
            try:
                user = authenticate_user(form_result['username'], form_result['password'])
            except InvalidUser, e:
                c.invalid_user = True
                return render('login.html')
        except formencode.Invalid, e:
            html = render('login.html')
            return formencode.htmlfill.render(html, errors=e.error_dict)
        else:
            session['user_id'] = user.id
            session.save()
            redirect(url(controller="main", action="index"))
    
    def logout(self):
        session.clear()
        session.save()
        redirect(url(controller="main", action="index"))
    
    def register(self):
        return render('register.html')
    
    def register_post(self):
        try:
            form_result = RegisterForm().to_python(request.POST)
        except formencode.Invalid, err:
            html = render('register.html')
            return formencode.htmlfill.render(html, errors=err.error_dict)
        else:
            user = User()
            user.username = form_result['username']
            user.first_name = form_result['first_name']
            user.last_name = form_result['last_name']
            user.email = form_result['email']
            user.password, user.salt = gen_hash_password(form_result['password'])
            user.save()
            return 'You are registered. <a href="/auth/login">login now</a>'
    
