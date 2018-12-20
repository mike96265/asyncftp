import asyncio
from asyncftp.Servers import AbstractServer
from asyncftp.FTPHandlers import FTPHandler
from asyncftp.Authorizer import DummyAuthorizer

authorizer = DummyAuthorizer()

authorizer.add_user('luvjoey', '1996829', 'd:/Users/luvjo/Documents/')

loop = asyncio.get_event_loop()

server = AbstractServer('0.0.0.0', 9998, FTPHandler, authorizer, loop)
loop.run_until_complete(server.start())
try:
    loop.run_forever()
except KeyboardInterrupt:
    loop.run_until_complete(server.close())
    loop.close()
