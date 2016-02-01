__author__ = 'andre'
from utils import make_pw_hash, valid_pw
import logging
from handlers import *
from google.appengine.ext import db
from google.appengine.api import memcache
import main



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