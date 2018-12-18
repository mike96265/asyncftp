import asyncio
from functools import wraps

loop = asyncio.get_event_loop()


def wrap_for_async(func):
    @wraps(func)
    async def wrap(*args, **kwargs):
        await asyncio.sleep(1)
        return print(func(*args, **kwargs))

    return wrap


@wrap_for_async
def add(a, b):
    return a + b


class A:
    a = 1


if __name__ == '__main__':
    a = A()
    a.a = 2
    b = A()
    print(b.a)
