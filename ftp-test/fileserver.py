from socket import *


def main():
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind(('0.0.0.0', 8000))
        sock.listen(5)
        client, (remote_ip, port) = sock.accept()
        print(f'connection from {remote_ip}:{port}')
        while client.recv(1024):
            pass


if __name__ == '__main__':
    main()
