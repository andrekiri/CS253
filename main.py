
import webapp2
from handlers import *
app = webapp2.WSGIApplication([('/blog/signup', SignupHandler),
                               ('/blog/?(?:.json)?', BlogListHandler),
                               ('/blog/login', LoginHandler),
                               ('/blog/logout', LogoutHandler),
                               ('/blog/welcome', WelcomeHandler),
                               ('/blog/([0-9]+)(?:.json)?', Permalink),
                               ('/blog/flush', FlashHandler),
                               ('/blog/newpost', BlogNewformHandler)], debug=True)