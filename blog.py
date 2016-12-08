import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

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

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.name))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

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

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
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
        u = cls.by_name(name) #can replace this cls with User
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    username = db.StringProperty(required = True)
    likes = db.IntegerProperty(default = 0)
    userlike = db.TextProperty(default = '|')

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFront(BlogHandler):
    def get(self):
        q = Post.all()
        q.order('-created')
        q.ancestor(blog_key())
        self.render('front.html', posts = q)

    def post(self):
        if not self.user:
            self.redirect('/login')
            return

        command = self.request.get("submit")
        if (command == "Delete"):
            post_id = int(self.request.get("delete"))
            post_key = db.Key.from_path('Post', post_id, parent=blog_key())
            valid_user = db.get(post_key).username
            if valid_user == self.user:
                db.delete(post_key)
                self.redirect('/')
            else:
                self.write(self.user)
                self.write(", you are not allowed to delete this post")

        elif (command == "Edit"):
            post_id = int(self.request.get("edit"))
            self.redirect("/blog/editpost/%s" % post_id)

        elif (command == "Like"):
            post_id = int(self.request.get("like"))
            post_key = db.Key.from_path('Post', post_id, parent=blog_key())
            post = db.get(post_key)
            valid_user = post.username
            newlikes = int(post.likes) + 1

            if valid_user != self.user and not self.user in post.userlike.split('|'):
                if not post.userlike:
                    post.userlike = ''

                post.likes = newlikes
                post.userlike = post.userlike + '|' + self.user
                db.put(post)
                self.redirect('/')
            else:
                self.write(self.user)
                self.write(", you are not allowed to like this post")

        elif (command == "Comment"):
            post_id = self.request.get("comment")
            self.redirect('/blog/comment/%s' % post_id)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, username=self.user)
            p.put()
            self.redirect('/')
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class EditPost(NewPost):
    def get(self, post_id):
        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(post_key)

        if not post:
            self.redirect('/')

        else:
            valid_user = post.username
            if valid_user == self.user:
                self.render("newpost.html", subject=post.subject, content=post.content)
            else:
                self.write(self.user)
                self.write(", you are not allowed to edit this post")

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')

        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(post_key)
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content
            db.put(post)
            self.redirect('/')
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

#comment
def comment_key(name = 'default'):
    return db.Key.from_path('comments', name)

class Comment(db.Model):
    username = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    post_id = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_post_id(cls, post_id):
        post_comment = cls.all().filter('post_id = ', post_id)
        if post_comment:
            return post_comment
        else:
            return False

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c = self)

class CommentPage(BlogHandler):
    def get(self, post_id):
        q = Comment.by_post_id(post_id)
        q.ancestor(comment_key())
        if q == False:
            self.render('front_comment.html', post_id = post_id)
        else:
            self.render('front_comment.html', comments = q, post_id = post_id)

    def post(self, comment_id):
        if not self.user:
            self.redirect('/login')
            return

        command = self.request.get("submit")
        if (command == "Delete"):
            _id = int(self.request.get("delete"))
            self.redirect("/blog/comment/deletecomment/%s" % _id)

        elif (command == "Edit"):
            _id = int(self.request.get("edit"))
            self.redirect("/blog/comment/editcomment/%s" % _id)

class NewComment(BlogHandler):
    def get(self, post_id):
        #check in case the post with this id doesnt exist
        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        q = db.get(post_key)
        if self.user and q:
            self.render("newcomment.html", post_id = post_id)
        else:
            self.redirect("/")

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')

        content = self.request.get('content')

        if content:
            comment = Comment(parent = comment_key(), content = content, username=self.user, post_id = post_id)
            comment.put()
            self.redirect('/blog/comment/%s' % post_id)
        else:
            error = "write your comment, please!"
            self.render("newcomment.html", content=content, error=error)

class EditComment(NewComment):
    def get(self, comment_id):
        _key = db.Key.from_path('Comment', int(comment_id), parent=comment_key())
        comment = db.get(_key)

        if not comment:
            self.redirect('/')

        else:
            valid_user = comment.username
            if valid_user == self.user:
                self.render("newcomment.html", content = comment.content, post_id = comment.post_id)
            else:
                self.write(self.user)
                self.write(", you are not allowed to edit this comment")

    def post(self, comment_id):
        if not self.user:
            self.redirect('/login')

        _key = db.Key.from_path('Comment', int(comment_id), parent=comment_key())
        comment = db.get(_key)
        content = self.request.get('content')

        if content:
            post_id = comment.post_id
            comment.content = content
            db.put(comment)
            self.redirect('/blog/comment/%s' % post_id)
        else:
            error = "write content, please!"
            self.render("newcomment.html", content=content, error=error)

class DeleteComment(BlogHandler):
    def get(self, comment_id):
        if not self.user:
            self.redirect('/login')

        _key = db.Key().from_path('Comment', int(comment_id), parent = comment_key())
        valid_user = db.get(_key).username
        if valid_user == self.user:
            post_id = db.get(_key).post_id
            db.delete(_key)
            self.redirect('/blog/comment/%s' % post_id)
        else:
            self.write(self.user)
            self.write(", you are not allowed to delete this comment")

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/welcome', Welcome),
                               ('/', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/comment/([0-9]+)', CommentPage),
                               ('/blog/comment/newcomment/([0-9]+)', NewComment),
                               ('/blog/comment/editcomment/([0-9]+)',EditComment),
                               ('/blog/comment/deletecomment/([0-9]+)',DeleteComment),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
