import tornado.httpserver
import tornado.websocket
import tornado.ioloop
import tornado.web
import socket
from uuid import uuid4

clients = []

testpayload = {
    'msgid' : str(uuid4()),
    'handler' : 'google_actions',
    'payload' : {
        'requestId' : 'ff36a3cc-ec34-11e6-b1a0-64510650abcf',
        'inputs' : [{
            'intent' : 'action.devices.SYNC'
        }]
    }
}

def handlepl(shhandler, shpayload):
    hasspayload = {
        'msgid' : str(uuid4()),
        'handler' : shhandler,
        'payload' : shpayload
    }
    return hasspayload

class ActionsHandler(tornado.web.RequestHandler):
    def post(self):
        preppayload = handlepl
        payload = preppayload('google_actions', self.request.body)
        print(payload)
        #print(self.request.body)

class WSHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        print('New Client: {}'.format(self))
        clients.append(self)
        self.write_message(testpayload)

    def on_message(self, message):
        print ('message recieved {}'.format(message))

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

