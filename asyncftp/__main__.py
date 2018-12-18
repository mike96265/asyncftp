import asyncio
from asyncftp.Servers import AbstractServer
from asyncftp.FTPHandlers import FTPHandler

loop = asyncio.get_event_loop()

server = AbstractServer(FTPHandler, '0.0.0.0', 9998)
loop.run_until_complete(server.start())
try:
    loop.run_forever()
except KeyboardInterrupt:
    loop.run_until_complete(server.close())
    loop.close()
