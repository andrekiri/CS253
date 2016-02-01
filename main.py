#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
from string import letters
import webapp2
import cgi
import re
import jinja2
import time
import logging
import hashlib
import hmac
import random
import json
age = 0
#import datetime.datetime as dt
from google.appengine.api import memcache
# if not hasattr(memcache, 'set'):
#     Client=None
#     memcache.setup_client(Client)
#     memcache = Client
from google.appengine.ext import db
#logging.basicConfig(filename='logfile.log',filemode= 'a')
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=False)

SECRET = 'imsosecret'

def hash_str(s):
        #return hashlib.sha256(s).hexdigest()
        return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
        return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
        val = h.split('|')[0]
        if h == make_secure_val(val):
                return val

def valid(input_text, input_type=None):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    if input_type == "username":
        return USER_RE.match(input_text)
    elif input_type == "password":
        return PASS_RE.match(input_text)
    elif input_type == "email":
        return not input_type or EMAIL_RE.match(input_text)
    else:
        return input_text

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for dummy_x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)





class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod   #mean that this method is static and is called on class (ex: User.by_id)
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())
        #return db.GqlQuery("SELECT * FROM User WHERE __key__=uid")

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        #u = db.GqlQuery("SELECT * FROM User WHERE name = name")
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Blogentry(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("blog.html", entries=self)


    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d





class MainHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'




class SignupHandler(MainHandler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render("signup.html")

    def post(self):
        self.uname = self.request.get('username')
        self.passw = self.request.get('password')
        self.vpassw = self.request.get('verify')
        self.email = self.request.get('email')


        have_error = False
        params = dict(username = self.uname, email = self.email)

        if not valid(self.uname, "username"):
            params['unameerror'] = "That's not a valid username."
            have_error = False
        if not valid(self.passw, "password"):
            params['passerror'] = "That's not a valid password."
            have_error = False
        if self.passw != self.vpassw:
            params['vpasserror'] = "Your passwords didn't match."
            have_error = False
        if not valid(self.email, "email"):
            params['emailerror'] = "That's not a valid email email."
            have_error = False

        if have_error:
            self.render("signup.html", **params)
        else:
            u = User.by_name(self.uname)
            if u:
                msg = 'That user already exists.'
                self.render('signup.html', unameerror = msg)
            else:
                u = User.register(self.uname, self.passw, self.email) # creates a new user
                u.put() # add him to database
                self.login(u) # set_cookie is called inside here to create the cookie
                self.redirect("/blog/welcome")

class LoginHandler(MainHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

class Permalink(MainHandler):
    def get(self, blog_id):
        entries = top_entries(blog_id)

        if not entries:
            self.error(404)
            return
        if self.format == 'html':
            self.render("blog.html", entries = entries, agee = str(int((time.time() - age)% 60//1)))
        else:
            self.render_json(entry.as_dict())

class LogoutHandler(MainHandler):
    def get(self):
        self.logout()
        self.redirect('/blog/signup')

class BlogListHandler(MainHandler):
    #logging.info("id:"+str(type(entry.key().id())))
    #a = Blogentry(subject = "test1sub", content = "test1 content")
    # a.put()
    #db.delete(Blogentry.all(keys_only=True))
    def get(self):
        global age 
        entries = top_entries('top')
        # entries = greetings = Blogentry.all().order('-created')

        #        logging.info(type(entries))

        if self.format == 'html':  
                     
            logging.info("elapsed   "+str(age))
            elapsed = str(int((time.time() - age)//1))
            self.render('blog.html', entries=entries, agee = elapsed, user = self.user)
        else:
            return self.render_json([e.as_dict() for e in entries])

def top_entries(key, update = False):
    global age
    entries = memcache.get(key)
    if entries is None or update:
        logging.error("DB QUERY")
        if key == 'top':
            entries = db.GqlQuery("select * from Blogentry order by created desc limit 10")
        else:
            entries = [Blogentry.get_by_id(int(key))]
       # entries = list(entries)
        memcache.set(key, entries)               
        age = time.time()

    
    return entries



#     def top_entries(update = False):
#         key = 'top'
#         entries = memcache.get(key)
#         global age
#         if entries is None or update:
#             logging.error("DB QUERY")
#             entries = db.GqlQuery("select * from Blogentry order by created desc limit 10")
#            # entries = list(entries)
#             memcache.set(key, entries)       
#             age = time.time()
# 
#         
#         return entries
class FlashHandler(MainHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')


class BlogNewformHandler(MainHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            a = Blogentry(subject=subject, content=content)
            a_key = a.put()
            top_entries('top', True)
            logging.info("AAAAAAAAAAAA  "+str(type(a_key.id())))
            top_entries(str(a_key.id()), True)
            time.sleep(1)
            self.redirect("/blog/%d" % a_key.id())
        else:
            error = "we need both a subject and some content"
            self.render("newpost.html", subject=subject, content=content, error=error)


class WelcomeHandler(MainHandler):
    def get(self):
        #username = self.request.get('username')
        if self.user:
            self.render('welcome.html', wuname = self.user.name)
        else:
            self.redirect('/blog/signup')

app = webapp2.WSGIApplication([('/blog/signup', SignupHandler),
                               ('/blog/?(?:.json)?', BlogListHandler),
                               ('/blog/login', LoginHandler),
                               ('/blog/logout', LogoutHandler),
                               ('/blog/welcome', WelcomeHandler),
                               ('/blog/([0-9]+)(?:.json)?', Permalink),
                               ('/blog/flush', FlashHandler),
                               ('/blog/newpost', BlogNewformHandler)], debug=True)