import asyncio

from Authorizer import DummyAuthorizer
from FTPHandlers import FTPHandler


async def main():
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous("d:/Users/luvjo/Documents", perm='elradfmwMT')

    handler = FTPHandler
    handler.authorizer = authorizer
    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: FTPHandler(loop), '0.0.0.0', 8888)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main(), debug=True)
