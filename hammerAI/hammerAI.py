import tornado.httpserver
import tornado.websocket
import tornado.ioloop
import tornado.web
import json
import socket
import re
import requests
import botocore
import boto3
from uuid import uuid4
from jose import jwt, exceptions as jose_exceptions
from const import SERVERS

wsclients = {}

#def __init__(self, mode, cognito_client_id=None, user_pool_id=None, region=None):
info = SERVERS['production']
cognito_client_id = info['cognito_client_id']
user_pool_id = info['user_pool_id']
region = info['region']

pool_url = 'https://cognito-idp.us-east-1.amazonaws.com/{}/.well-known/jwks.json'.format(user_pool_id)
bearerreg = re.compile('Bearer\s(.*)')

def get_cognito_user(accesstoken):
    client = boto3.client('cognito-idp', region_name=region)
    print('AT: {}'.format(accesstoken))
    resp = client.get_user(
        AccessToken = accesstoken
    )
    print('IDP: {}'.format(resp))

    return resp

def aws_key_dict(aws_region, aws_user_pool):
    aws_data = requests.get(pool_url)
    aws_jwt = json.loads(aws_data.text)
    # We want a dictionary keyed by the kid, not a list.
    result = {}
    for item in aws_jwt['keys']:
        result[item['kid']] = item

    return result

def get_client_sub_from_access_token(aws_region, aws_user_pool, token):
    """ Pulls the client ID out of an Access Token
    """
    claims = get_claims(aws_region, aws_user_pool, token)
    if claims.get('token_use') != 'access':
        raise ValueError('Not an access token')

    return claims.get('sub')

def get_user_sub_from_id_token(token):
    payload = jwt.get_unverified_claims(token)
    return payload.get('sub')

def get_claims(aws_region, aws_user_pool, token, audience=None):
    # header, _, _ = get_token_segments(token)
    header = jwt.get_unverified_header(token)
    kid = header['kid']

    verify_url = pool_url

    keys = aws_key_dict(aws_region, aws_user_pool)

    key = keys.get(kid)

    kargs = {"issuer": verify_url}
    if audience is not None:
        kargs["audience"] = audience

    claims = jwt.decode(
        token,
        key,
        audience=cognito_client_id,
        options={
            'verify_exp': False,
        }
    )

    return claims

def get_intended_user(authheader):
    authtokenmatch = bearerreg.match(authheader)
    authtoken = authtokenmatch.group(1)
    intended_user = get_user_sub_from_id_token(authtoken)

    return intended_user

def handlepl(shhandler, shpayload):
    hasspayload = {
        'msgid' : str(uuid4()),
        'handler' : shhandler,
        'payload' : shpayload
    }
    return hasspayload

def deliverpayload(uuid, payload):
    wsclients[uuid].
    
class ActionsHandler(tornado.web.RequestHandler):
    def post(self):
        authtokenmatch = bearerreg.match(self.request.headers['AUTHORIZATION'])
        tokes = authtokenmatch.group(1)
        tgtclient = get_client_sub_from_access_token(region, user_pool_id, tokes)
        gapayload = json.loads(self.request.body)
        payload = handlepl('google_actions', gapayload)
        wsclients[tgtclient].write_message(payload)

class WSHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        print('Connection Opened')
        wsclients[get_intended_user(self.request.headers['AUTHORIZATION'])] = self
        print('User: {}'.format(get_intended_user(self.request.headers['AUTHORIZATION'])))

    def on_message(self, message):
        print ('message recieved: {}'.format(message))

    def on_close(self):
        print('connection closed')

    def check_origin(self, origin):
        return True

application = tornado.web.Application([
    (r'/ws', WSHandler),
    (r'/gactions', ActionsHandler),
])

if __name__ == "__main__":
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(8080)
    myIP = socket.gethostbyname(socket.gethostname())
    print('*** Websocket Server Started at {} ***'.format(myIP))
    tornado.ioloop.IOLoop.instance().start()

