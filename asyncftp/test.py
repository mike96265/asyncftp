import asyncio
from functools import wraps


async def atest(a):
    print(a)
    await asyncio.sleep(0)

    await xxx(a)
    await asyncio.sleep(0)
    print('ending %s' % a)


async def xxx(a):
    print('xxx %s' % a)


if __name__ == '__main__':
    a = asyncio.gather(atest('a'), atest('b'))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(a)
