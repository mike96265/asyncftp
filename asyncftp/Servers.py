import asyncio
from asyncio import StreamReader, StreamWriter, AbstractEventLoop
import logging
import socket
from typing import Type

from asyncftp.Authorizer import AbstractAuthorizer, DummyAuthorizer
from asyncftp.FTPHandlers import FTPHandler

logger = logging.getLogger('asyncio')


class AbstractServer:
    max_cons = 512
    max_cons_per_ip = 0
    handler_class = FTPHandler
    authorizer = DummyAuthorizer()

    def __init__(self,
                 host: str, port: int = 0,
                 handler_class: Type[FTPHandler] = None,
                 authorizer: AbstractAuthorizer = None,
                 loop: AbstractEventLoop = None,
                 **kwargs):
        self.loop = loop if loop else asyncio.get_running_loop()
        self.server_host = host
        self.server_port = port
        self._start_server_extra_arguments = kwargs
        if 'ssl' in kwargs:
            self.ssl = kwargs['ssl']
        else:
            self.ssl = None
        if handler_class:
            self.handler_class = handler_class
        if authorizer:
            self.authorizer = authorizer
        handler_class.set_authorizer(authorizer)
        self.ip_map = []

    async def start(self):
        _server = await asyncio.start_server(self.dispatcher, self.server_host, self.server_port,
                                             loop=self.loop, ssl=self.ssl, **self._start_server_extra_arguments)
        for sock in _server.sockets:
            if sock.family in (socket.AF_INET, socket.AF_INET6):
                host, port, *_ = sock.getsockname()
                logger.info("serving on %s:%s", host, port)

    async def dispatcher(self, reader: StreamReader, writer: StreamWriter):
        remote_host, remote_port, *_ = writer.transport.get_extra_info('peername', ('', ''))
        handler = self.handler_class(remote_host, remote_port, self, self.loop, reader, writer)
        self.ip_map.append(remote_host)
        if not self._accept_new_cons():
            await handler.handle_max_cons()
            return
        if not self._accept_from_given_ip(remote_host):
            await handler.handle_max_cons_per_ip()
            return
        await handler.handle()

    def _accept_new_cons(self):
        if not self.max_cons:
            return True
        else:
            return self._map_len() <= self.max_cons

    def _accept_from_given_ip(self, ip):
        if not self.max_cons_per_ip:
            return True
        else:
            return self.ip_map.count(ip) <= self.max_cons_per_ip

    def _map_len(self):
        return len(self.ip_map)

    async def close(self):
        pass
