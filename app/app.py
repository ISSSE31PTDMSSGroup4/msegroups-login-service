import requests

from datetime import datetime, timedelta
from flask import Flask, render_template_string, session, redirect, request, url_for, make_response, abort, Response, jsonify
try:
  from . import config
except:
  import config
import flask_login
import os
from jose import jwt as jose_jwt
from urllib.parse import urlparse
##JWT related

from flask_jwt_extended import create_access_token, set_access_cookies, create_refresh_token, unset_jwt_cookies
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from Crypto.PublicKey import RSA
from jwcrypto import jwk



app = Flask(__name__)
app.secret_key = config.SECRET_KEY

##generate RSA keys
key = RSA.generate(2048)
private_key = key.export_key('PEM').decode('utf-8')
print(private_key)
public_key = key.publickey().export_key('PEM').decode('utf-8')
print(public_key)
app.config['JWT_COOKIE_SECURE'] = True
app.config["JWT_PRIVATE_KEY"] = private_key  
app.config["JWT_TOKEN_LOCATION"] = "cookies"
app.config['JWT_PUBLIC_KEY'] = public_key
app.config['JWT_ALGORITHM'] = 'RS256'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 1500  #5 seconds
jwt = JWTManager(app)
jwk_key = jwk.JWK.from_pem(bytes(public_key, 'utf-8')).export_public()


COGNITO_JWKS_URL = (
  f"https://cognito-idp.{config.AWS_REGION}.amazonaws.com/{config.AWS_COGNITO_USER_POOL_ID}/.well-known/jwks.json"
)
print(COGNITO_JWKS_URL)
COGNITO_JWKS = requests.get(COGNITO_JWKS_URL).json()["keys"]

login_manager = flask_login.LoginManager()
login_manager.init_app(app)


def random_hex_bytes(n_bytes):
  """Create a hex encoded string of random bytes"""
  return os.urandom(n_bytes).hex()

def is_safe_url(url):
  if urlparse(url).netloc!= '':
    return False
  else: return True

def verify(token, access_token=None):
  """Verify a cognito JWT"""
  # get the key id from the header, locate it in the cognito keys
  # and verify the key
  header = jose_jwt.get_unverified_header(token)
  key = [k for k in COGNITO_JWKS if k["kid"] == header['kid']][0]
  id_token = jose_jwt.decode(token,
                        key,
                        audience=config.AWS_COGNITO_USER_POOL_CLIENT_ID,
                        access_token=access_token)
  return id_token


@app.route("/")
@app.route("/index")
def index():
  return "hello world"

@app.route('/profile')
@jwt_required()
def profile():
  identity = get_jwt_identity()
  return jsonify({"user": identity})

@app.route('/.well-known/jwks.json')
def key():
  return Response(jwk_key, mimetype='application/json')

@app.route("/login")
@jwt_required(optional=True)
def login():
  identity = get_jwt_identity()
  if identity:
    return redirect("/")
  """Login route"""
  # http://docs.aws.amazon.com/cognito/latest/developerguide/loginendpoint.html
  session['csrf_state'] = random_hex_bytes(8)
  #before redirecting, check 'next' route
  next_page = request.args.get('next')
  if next_page and is_safe_url(next_page): 
    #https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
    session['next']=next_page
  cognito_login = (
    f"{config.AWS_COGNITO_DOMAIN}/login?response_type=code&client_id={config.AWS_COGNITO_USER_POOL_CLIENT_ID}&state={session['csrf_state']}&redirect_uri={config.AWS_COGNITO_REDIRECT_URL}"
  )
  print(cognito_login)
  return redirect(cognito_login)


@app.route("/logout")
def logout():
  """Logout route"""
  # http://docs.aws.amazon.com/cognito/latest/developerguide/logoutendpoint.html
  cognito_logout = (
    f"{config.AWS_COGNITO_DOMAIN}/logout?response_type=code&client_id={config.AWS_COGNITO_USER_POOL_CLIENT_ID}&logout_uri={config.AWS_COGNITO_LOGOUT_URL}"
  )
  resp = make_response(redirect(cognito_logout))
  unset_jwt_cookies(resp)
  return resp




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
    session['csrf_state']=None
    verify(response.json()["access_token"])
    id_token = verify(response.json()["id_token"],
                      response.json()["access_token"])
    print(id_token)
    #now the user is logged in
    #set cookie so frontend knows that user is logged in
    if session.get("next") == None:
      resp = make_response(redirect('/'))
    else:
      resp = make_response(redirect(session['next']))
      session['next']=''
    access_token = create_access_token(identity=id_token['email'])
    refresh_token = create_refresh_token(identity=id_token['email'])
    resp.set_cookie('refresh_token_cookie',
                        refresh_token,
                        httponly=True,
                        secure=True)  #14day
    set_access_cookies(resp, access_token)
    resp.set_cookie("logged_in","true", httponly=False)
    return resp


  else:
    print(response.status_code)
    print(response.text)

  return render_template_string("""<p>Something went wrong</p>""")


if __name__ == "__main__":
  app.run(port=5000)
