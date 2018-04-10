import asyncio
import aiohttp.web
from aiohttp import web

import logging
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

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)


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
    logger.debug('Prepared Payload. ID: {} Contents {}'.format(hasspayload['msgid'], hasspayload['payload']))
    return hasspayload

async def fetchpayload(msgid):
    fetchedpayload = None
    logger.info('Waiting for: {}'.format(msgid))
    while fetchedpayload is None:
        await asyncio.sleep(0.2)
        fetchedpayload = msgqueue.pop(msgid)
    logger.info('Fetched: {}'.format(fetchedpayload['msgid']))
    payload = fetchedpayload['payload']
    return payload

async def ActionsHandler(request):
    logger.info('Request received from Google')
    authtokenmatch = bearerreg.match(request.headers['AUTHORIZATION'])
    gaAuthToken = authtokenmatch.group(1)
    tgtclient = get_client_sub_from_access_token(region, user_pool_id, gaAuthToken)
    logger.debug('Request intended for {}'.format(tgtclient))
    gapayload = await request.json()
    payload = handlepl('google_actions', gapayload)
    #msgid = payload['msgid']
    await wsclients[tgtclient].send_json(payload)
    response = await fetchpayload(payload['msgid'])
    return web.Response(text=json.dumps(response), status=200)

async def WSHandler(request):
    logging.info('Websocket connection starting')
    ws = aiohttp.web.WebSocketResponse()
    await ws.prepare(request)
    logger.info('Websocket connection ready')
    wsclients[get_intended_user(request.headers['AUTHORIZATION'])] = ws
    async for msg in ws:
        if msg.type != aiohttp.WSMsgType.TEXT:
            logger.warn('Received non-Text message: {}'.format(msg.type))
            break
        msg = msg.json()
        async def storemsg(message):
            logging.debug('Storing MSGID: {}'.format(message['msgid']))
            msgqueue[message['msgid']] = message
        await storemsg(msg)

    logger.info('Websocket connection closed')
    return ws


def main():
    loop = asyncio.get_event_loop()
    app = aiohttp.web.Application(loop=loop)
    app.router.add_route('*', '/gactions', ActionsHandler)
    app.router.add_route('GET', '/ws', WSHandler)
    aiohttp.web.run_app(app, host=HOST, port=PORT)


if __name__ == '__main__':
    main()
