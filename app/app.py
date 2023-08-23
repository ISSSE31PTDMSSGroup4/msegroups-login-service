import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime
from flask import Flask, render_template_string, session, redirect, request, url_for, make_response, abort
from . import config
import flask_login
import os
from jose import jwt

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

JWKS_URL = (
  f"https://cognito-idp.{config.AWS_REGION}.amazonaws.com/{config.AWS_COGNITO_USER_POOL_ID}/.well-known/jwks.json"
)
print(JWKS_URL)
JWKS = requests.get(JWKS_URL).json()["keys"]

login_manager = flask_login.LoginManager()
login_manager.init_app(app)


def random_hex_bytes(n_bytes):
  """Create a hex encoded string of random bytes"""
  return os.urandom(n_bytes).hex()


class User(flask_login.UserMixin):
  """Standard flask_login UserMixin"""
  pass


@login_manager.user_loader
def user_loader(session_token):
  """Populate user object, check expiry"""
  if "expires" not in session or not isinstance(session['expires'], int):
    return None
  expires = datetime.utcfromtimestamp(session['expires'])
  expires_seconds = (expires - datetime.utcnow()).total_seconds()
  if expires_seconds < 0:
    return None
  user = User()
  user.id = session_token
  return user


@app.route("/")
@app.route("/index")
def index():
  return abort(404)



@app.route("/login")
def login():
  """Login route"""
  # http://docs.aws.amazon.com/cognito/latest/developerguide/loginendpoint.html
  session['csrf_state'] = random_hex_bytes(8)
  cognito_login = (
    f"{config.AWS_COGNITO_DOMAIN}/login?response_type=code&client_id={config.AWS_COGNITO_USER_POOL_CLIENT_ID}&state={session['csrf_state']}&redirect_uri={config.AWS_COGNITO_REDIRECT_URL}"
  )
  return redirect(cognito_login)


@app.route("/logout")
def logout():
  """Logout route"""
  # http://docs.aws.amazon.com/cognito/latest/developerguide/logoutendpoint.html
  flask_login.logout_user()
  cognito_logout = (
    f"{config.AWS_COGNITO_DOMAIN}/logout?response_type=code&client_id={config.AWS_COGNITO_USER_POOL_CLIENT_ID}&logout_uri={config.AWS_COGNITO_LOGOUT_URL}"
  )
  session['id_token'] = ''
  session['expires'] = ''
  session['refresh_token'] = ''
  return redirect(cognito_logout)


def verify(token, access_token=None):
  """Verify a cognito JWT"""
  # get the key id from the header, locate it in the cognito keys
  # and verify the key
  header = jwt.get_unverified_header(token)
  key = [k for k in JWKS if k["kid"] == header['kid']][0]
  id_token = jwt.decode(token,
                        key,
                        audience=config.AWS_COGNITO_USER_POOL_CLIENT_ID,
                        access_token=access_token)
  return id_token


@app.route("/postlogin")
def callback():
  """Exchange the 'code' for Cognito tokens"""
  #http://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html
  csrf_state = request.args.get('state')
  code = request.args.get('code')
  request_parameters = {
    'grant_type': 'authorization_code',
    'client_id': config.AWS_COGNITO_USER_POOL_CLIENT_ID,
    'code': code,
    "redirect_uri": config.AWS_COGNITO_REDIRECT_URL
  }
  response = requests.post("%s/oauth2/token" % config.AWS_COGNITO_DOMAIN,
                           data=request_parameters)

  # the response:
  # http://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
  if response.status_code == requests.codes.ok and csrf_state == session[
      'csrf_state']:
    verify(response.json()["access_token"])
    id_token = verify(response.json()["id_token"],
                      response.json()["access_token"])
    print(id_token)
    user = User()
    user.id = id_token["cognito:username"]
    session['expires'] = int(id_token["exp"])
    session['access_token'] = response.json()["access_token"]
    session['refresh_token'] = response.json()["refresh_token"]
    flask_login.login_user(user, remember=True)
    #now the user is logged in
    #set cookie so frontend knows that user is logged in
    resp = make_response(redirect('/'))
    resp.set_cookie("csrf_js", session['csrf_state'], expires=datetime.utcnow()+86400, httponly=False)
    resp.set_cookie("authenticated","true", expires=datetime.utcnow()+86400, httponly=False)
    return resp


  else:
    print(response.status_code)
    print(response.text)

  return render_template_string("""<p>Something went wrong</p>""")


if __name__ == "__main__":
  app.run(port=5000)
