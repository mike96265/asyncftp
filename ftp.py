import asyncio


class FtpServerHandler:
    pass


class FtpProtocol(asyncio.Protocol):

    def __init__(self, loop):
        self.transport = None
        self.ftp_session = None
        self.loop = loop

    def connection_made(self, transport):
        """
        when ftp client reached,determine to say hello or refuse connection
        :param transport:
        :return:
        """
        self.transport = transport

    def data_received(self, data):
        """
        :param data:
        :return:
        """
