import time
from socket import *
import os

somefile = 'd:\\Users\\luvjo\\Documents\\学习资料\\算法第4版.pdf'


def without_sendfile(somefile):
    with open(f"{somefile}", "rb") as file:
        sock = socket()
        sock.connect(("192.168.0.102", 8000))
        while True:
            chunk = file.read(65536)
            if not chunk:
                break  # EOF
            sock.sendall(chunk)


def with_sendfile(somefile):
    with open(f"{somefile}", "rb") as file:
        blocksize = os.path.getsize(f"{somefile}")
        sock = socket()
        sock.connect(("127.0.0.1", 8021))
        offset = 0
        while True:
            sent = os.sendfile(sock.fileno(), file.fileno(), offset, blocksize)
            offset += sent
            if sent == 0:
                break


def main():
    without_sendfile(somefile)


if __name__ == '__main__':
    start = time.time()
    main()
    end = time.time()
    print(f'{end - start}')
