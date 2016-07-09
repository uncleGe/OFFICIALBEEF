#!/usr/bin/env python

from google.appengine.ext.webapp import template
from google.appengine.ext import ndb

import logging
import os.path

import os
import re
import webapp2

from webapp2_extras import auth
from webapp2_extras import sessions

from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

import jinja2
from string import letters
from google.appengine.ext import db
import time
import datetime


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							  autoescape = True)
logged_in = False


def user_required(handler):
	"""
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
    """
	def check_login(self, *args, **kwargs):
		auth = self.auth
		if not auth.get_user_by_session():
			self.redirect(self.uri_for('login_alert'), abort=True)
		else:
			return handler(self, *args, **kwargs)

	return check_login

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def render_post(reponse, post):
	reponse.out.write('<b>' + post.subject + '</b><br>')
	response.out.write(post.content)

	response.out.write(post.content1)
	response.out.write(post.content2)

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)
	

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	@webapp2.cached_property
  	def auth(self):
  		"""Shortcut to access the auth instance as a property."""
  		return auth.get_auth()

	@webapp2.cached_property
	def user_info(self):
	    """Shortcut to access a subset of the user attributes that are stored
	    in the session.
	    The list of attributes to store in the session is specified in
	      config['webapp2_extras.auth']['user_attributes'].
	    :returns
	      A dictionary with most user information
	    """

	    return self.auth.get_user_by_session()

	@webapp2.cached_property
	def user(self):
		"""
		Shortcut to access the current logged in user.
	    Unlike user_info, it fetches information from the persistence layer and
	    returns an instance of the underlying model.
	    :returns
	      The instance of the user model associated to the logged in user.
	    """
		u = self.user_info
		return self.user_model.get_by_id(u['user_id']) if u else None

	@webapp2.cached_property
	def user_model(self):
	    """Returns the implementation of the user model.
	    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
	    """    
	    return self.auth.store.user_model

	@webapp2.cached_property
	def session(self):
		"""Shortcut to access the current session."""
		return self.session_store.get_session(backend="datastore")

	def render_template(self, view_filename, params=None):
		if not params:
		  params = {}
		user = self.user_info
		params['user'] = user
		path = os.path.join(os.path.dirname(__file__), 'templates', view_filename)
		self.response.out.write(template.render(path, params))

	def display_message(self, message):
		"""Utility function to display a template with a simple message."""
		params = {
		  'message': message
		}
		self.render_template('message.html', params)

  	# This is needed for webapp2 sessions to work
	def dispatch(self):

      	# Get a session store for this request
		self.session_store = sessions.get_store(request=self.request)

		try:
			# Dispatch the request
			webapp2.RequestHandler.dispatch(self)
		finally:
			# Save all sessions
			self.session_store.save_sessions(self.response)


class Post7(db.Model):
	subject = db.StringProperty(required = True)
	content = db.StringProperty()
	content1 = db.TextProperty()
	content2 = db.TextProperty()
	
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		self._render_text1 = self.content1.replace('\n', '<br>')
		self._render_text2 = self.content2.replace('\n', '<br>')

		# Timezone adjustment
		timeString = str(self.created)
		hr_str = (timeString[11:13])
		hr = int(hr_str)

		if hr >= 4:
			hr -= 4
		else:
			hr += 20

		if hr < 9:
			hr_str = "0" + str(hr)
		else:
			hr_str = str(hr)

		ESTstring = timeString[:11] + hr_str + timeString[13:]
		self.EST = datetime.datetime.strptime(ESTstring, "%Y-%m-%d %H:%M:%S.%f")

		return render_str("post.html", p = self)


class LogFrontList(BlogHandler):
	def get(self):
		posts = db.GqlQuery("select * from Post7 order by created desc limit 100")
		self.render('logged_in_front_list.html', posts = posts)

	@user_required
	def post(self):
		subject = "OFFICIAL BEEF"
		content = self.request.get('content')
		content1 = self.request.get('content1')
		content2 = self.request.get('content2')

		if content:
			p = Post7(parent = blog_key(), subject = subject, content = content, content1 = content1, content2 = content2)
			p.put()
			self.render("permalink.html")


class LogFront(BlogHandler):
	def get(self):
		posts = db.GqlQuery("select * from Post7 order by created desc limit 100")
		self.render('logged_in_front.html', posts = posts)

	@user_required
	def post(self):
		subject = "OFFICIAL BEEF"
		content = self.request.get('content')
		content1 = self.request.get('content1')
		content2 = self.request.get('content2')

		if content:
			p = Post7(parent = blog_key(), subject = subject, content = content, content1 = content1, content2 = content2)
			p.put()
			self.render("permalink.html")


class BlogFront(BlogHandler):
	def get(self):
		posts = db.GqlQuery("select * from Post7 order by created desc limit 100")
		self.render('front.html', posts = posts)

	@user_required
	def post(self):
		subject = "OFFICIAL BEEF"
		content = self.request.get('content')
		content1 = self.request.get('content1')
		content2 = self.request.get('content2')

		if content:
			p = Post7(parent = blog_key(), subject = subject, content = content, content1 = content1, content2 = content2)
			p.put()
			self.render("permalink.html")


class PostPage(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post7', int(post_id), parent=blog_key())
		post = db.get(key)

		self.render("permalink.html", post = post)


class MainHandler(BlogHandler):
  def get(self):
    self.render_template('home.html')


class SignupHandler(BlogHandler):
  def get(self):
    self.render_template('signup.html')

  def post(self):
    user_name = self.request.get('username')
    email = self.request.get('email')
    name = self.request.get('name')
    password = self.request.get('password')
    last_name = self.request.get('lastname')

    unique_properties = ['email_address']
    user_data = self.user_model.create_user(user_name,
      unique_properties,
      email_address=email, name=name, password_raw=password,
      last_name=last_name, verified=False)
    if not user_data[0]: # user_data is a tuple
      self.display_message('Unable to create user for email %s because of \
        duplicate keys %s' % (user_name, user_data[1]))
      return
    
    user = user_data[1]
    user_id = user.get_id()

    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='v', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Please click the following link to prove you are not a robot: \
          <a href="{url}">{url}</a>'

    self.display_message(msg.format(url=verification_url))


class ForgotPasswordHandler(BlogHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')

    user = self.user_model.get_by_auth_id(username)
    if not user:
      logging.info('Could not find any user entry for username %s', username)
      self._serve_page(not_found=True)
      return

    user_id = user.get_id()
    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='p', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Send an email to user in order to reset their password. \
          They will be able to do so by visiting <a href="{url}">{url}</a>'

    self.display_message(msg.format(url=verification_url))
  
  def _serve_page(self, not_found=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'not_found': not_found
    }
    self.render_template('forgot.html', params)


class VerificationHandler(BlogHandler):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']

    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token,
      'signup')

    if not user:
      logging.info('Could not find any user with id "%s" signup token "%s"',
        user_id, signup_token)
      self.abort(404)
    
    # Store user data in the session
    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

    if verification_type == 'v':
      
      # Remove signup token, we don't want users to come back with an old link
      self.user_model.delete_signup_token(user.get_id(), signup_token)

      if not user.verified:
        user.verified = True
        user.put()

      self.redirect(self.uri_for('homeLogged'))
      
      self.display_message('User email address has been verified.')
      return

    elif verification_type == 'p':
      
      # Supply user to the page
      params = {
        'user': user,
        'token': signup_token
      }
      self.render_template('resetpassword.html', params)
    else:
      logging.info('verification type not supported')
      self.abort(404)


class SetPasswordHandler(BlogHandler):

  @user_required
  def post(self):
    password = self.request.get('password')
    old_token = self.request.get('t')

    if not password or password != self.request.get('confirm_password'):
      self.display_message('passwords do not match')
      return

    user = self.user
    user.set_password(password)
    user.put()

    # Remove signup token, we don't want users to come back with an old link
    self.user_model.delete_signup_token(user.get_id(), old_token)
    
    self.display_message('Password updated')


class LoginHandler(BlogHandler):

  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')
    try:
      u = self.auth.get_user_by_password(username, password, remember=True,
        save_session=True)
      self.redirect(self.uri_for('homeLogged'))
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Login failed for user %s because of %s', username, type(e))
      self._serve_page(True)

  def _serve_page(self, failed=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'failed': failed
    }
    self.render_template('login.html', params)


class LoginAlert(BlogHandler):
  def get(self):
    self.render('login_alert.html')


class LogoutHandler(BlogHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('home'))


class AuthenticatedHandler(BlogHandler):
  @user_required
  def get(self):
    self.render_template('authenticated.html')


class BaseHandler(BlogHandler):
	def get(self):
		self.render('base.html')


config = {
	'webapp2_extras.auth': {
		'user_model': 'models.User',
		'user_attributes': ['name']
	},
	'webapp2_extras.sessions': {
		'secret_key': 'YOUR_SECRET_KEY'
	}
}


app = webapp2.WSGIApplication([ webapp2.Route('/', BlogFront, name='home'),
								webapp2.Route('/base', BaseHandler, name='base'),
								webapp2.Route('/logged_in', LogFront, name='homeLogged'),
								webapp2.Route('/logged_in_list', LogFrontList, name='homeLoggedList'),
							    webapp2.Route('/([0-9]+)', PostPage),
								webapp2.Route('/signup', SignupHandler),
							    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
							      handler=VerificationHandler, name='verification'),
							    webapp2.Route('/password', SetPasswordHandler),
							    webapp2.Route('/login', LoginHandler, name='login'),
   							    webapp2.Route('/login_alert', LoginAlert, name='login_alert'),
							    webapp2.Route('/logout', LogoutHandler, name='logout'),
							    webapp2.Route('/forgot', ForgotPasswordHandler, name='forgot'),
							    webapp2.Route('/authenticated', AuthenticatedHandler, name='authenticated')
							   ],
							    debug = True, config=config)

logging.getLogger().setLevel(logging.DEBUG)