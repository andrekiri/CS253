__author__ = 'andrekiri'

import hmac

import re
import hashlib

from string import letters


SECRET = 'imsosecret'


import random
dbg = False


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


