from typing import TYPE_CHECKING
from asyncio import Protocol

if TYPE_CHECKING:
    from .FTPHandlers import FTPHandler


class PassiveDTP(Protocol):

    def __init__(self, cmd_channel: 'FTPHandler', extmode: bool = False):
        self.cmd_channel = cmd_channel
        self.log = cmd_channel.log
        self.log_exception = cmd_channel.log_exception
        local_ip = self.cmd_channel.transport.get_extra_info('socket').getsockname()[0]
        if local_ip in self.cmd_channel.masquerade_address_map:
            masqueraded_ip = self.cmd_channel.masquerade_address_map[local_ip]
        elif self.cmd_channel.masquerade_address:
            masqueraded_ip = self.cmd_channel.masquerade_address
        else:
            masqueraded_ip = None

        if self.cmd_channel.server


class ActiveDTP:

    def __init__(self):
        pass
