import asyncio

# class EchoServerProtocol(asyncio.Protocol):
#     def connection_made(self, transport):
#         peername = transport.get_extra_info('peername')
#         print('Connection from {}'.format(peername))
#         self.transport = transport
#
#     def data_received(self, data):
#         message = data.decode()
#         print('Data received: {!r}'.format(message))
#
#         print('Send: {!r}'.format(message))
#         self.transport.write(data)
#
#         print('Close the client socket')
#         self.transport.close()
#
#
# async def main():
#     # Get a reference to the event loop as we plan to use
#     # low-level APIs.
#     loop = asyncio.get_running_loop()
#
#     server = await loop.create_server(
#         lambda: EchoServerProtocol(),
#         '127.0.0.1', 8888)
#
#     async with server:
#         await server.serve_forever()

import asyncio


async def handle_echo(reader, writer):
    data = await reader.read(100)
    message = data.decode()
    addr = writer.get_extra_info('peername')

    print(f"Received {message!r} from {addr!r}")

    print(f"Send: {message!r}")
    writer.write(data)
    await writer.drain()

    print("Close the connection")
    writer.close()


async def main():
    server = await asyncio.start_server(
        handle_echo, '127.0.0.1', 8888)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
