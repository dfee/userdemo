import logging

from pylons import request, response, session, tmpl_context as c, url
from pylons.controllers.util import abort, redirect

from userdemo.lib.base import BaseController, render

from decorator import decorator

def require_login(func, *args, **kwargs):
    """ Checks to see if user_id is in session """
    if not 'user_id' in session:
        redirect(url(controller='auth', action='login'), code=303)
    return func(*args, **kwargs)
require_login = decorator(require_login)

log = logging.getLogger(__name__)

class MainController(BaseController):
    @require_login
    def index(self):
        return 'You are logged in! Click <a href="/auth/logout">here</a> to logout.'
