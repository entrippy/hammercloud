import asyncio
import aiohttp.web

import os
import json
import socket
import re
import requests
import botocore
import boto3
from uuid import uuid4
from jose import jwt, exceptions as jose_exceptions
from const import SERVERS

HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 8080))

wsclients = {}
msgqueue = {}
bearerreg = re.compile('Bearer\s(.*)')

info = SERVERS['production']
cognito_client_id = info['cognito_client_id']
user_pool_id = info['user_pool_id']
region = info['region']

pool_url = 'https://cognito-idp.us-east-1.amazonaws.com/{}/.well-known/jwks.json'.format(user_pool_id)

def aws_key_dict(aws_region, aws_user_pool):
    aws_data = requests.get(pool_url)
    aws_jwt = json.loads(aws_data.text)
    # We want a dictionary keyed by the kid, not a list.
    result = {}
    for item in aws_jwt['keys']:
        result[item['kid']] = item

    return result

def get_client_sub_from_access_token(aws_region, aws_user_pool, token):
    claims = get_claims(aws_region, aws_user_pool, token)
    if claims.get('token_use') != 'access':
        raise ValueError('Not an access token')
    return claims.get('sub')

def get_user_sub_from_id_token(token):
    payload = jwt.get_unverified_claims(token)
    return payload.get('sub')

def get_claims(aws_region, aws_user_pool, token, audience=None):
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

async def fetchpayload(msgid):
    fetchedpayload = None
    print('Fetching: {}'.format(msgid))
    while fetchedpayload is None:
        print('Polling Queue')
        #print('Queue Contains on Fetch: {}'.format(msgqueue))
        fetchedpayload = msgqueue.get(msgid)
    print('Fetched: {}'.format(fetchedpayload))
    return payload

async def ActionsHandler(request):
    authtokenmatch = bearerreg.match(request.headers['AUTHORIZATION'])
    gaAuthToken = authtokenmatch.group(1)
    tgtclient = get_client_sub_from_access_token(region, user_pool_id, gaAuthToken)
    gapayload = await request.json()
    payload = handlepl('google_Actions', gapayload)
    await wsclients[tgtclient].send_json(payload)
    async for msg in wsclients[tgtclient]:
        if msg.type != aiohttp.WSMsgType.TEXT:
            disconnect_warn = 'Received non-Text message: {}'.format(msg.type)
            break
        response = msg.json()
        break
    return response

async def WSHandler(request):
    print('Websocket connection starting')
    ws = aiohttp.web.WebSocketResponse()
    await ws.prepare(request)
    print('Websocket connection ready')
    wsclients[get_intended_user(request.headers['AUTHORIZATION'])] = ws
#    async for msg in ws:
#        if msg.type != aiohttp.WSMsgType.TEXT:
#            disconnect_warn = 'Received non-Text message: {}'.format(msg.type)
#            break
#        msg = msg.json()
#        async def storemsg(message):
#            print('Storing MSGID: {}'.format(message['msgid']))
#            msgqueue[message['msgid']] = message
#            print('Queue Contains: {}'.format(msgqueue))
#        await storemsg(msg)
#
#        #print(msg.data)
#        if msg.data == 'close':
#            await ws.close()
#        else:
#            await ws.send_str(msg.data + '/answer')

    print('Websocket connection closed')
    return ws


def main():
    loop = asyncio.get_event_loop()
    app = aiohttp.web.Application(loop=loop)
    app.router.add_route('*', '/gactions', ActionsHandler)
    app.router.add_route('GET', '/ws', WSHandler)
    aiohttp.web.run_app(app, host=HOST, port=PORT)


if __name__ == '__main__':
    main()
