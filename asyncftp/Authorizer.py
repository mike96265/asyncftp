import os
from typing import TYPE_CHECKING, Union
import warnings

if TYPE_CHECKING:
    from asyncftp.FTPHandlers import FTPHandler


class AuthorizerError(Exception):
    """Base class for authorizer exceptions"""


class AuthenticationFailed(Exception):
    """Exception raised when authentication fails for any reason."""


class AbstractAuthorizer:
    _single_instance = None

    def add_user(self, username: str, password: str, homedir: str, perm: str = 'erl',
                 msg_login: str = "Login successful", msg_quit: str = "Goodbye"):
        """
        Add a user.
        :param username: username for identification, as the argument of ftp USER command
        :param password: password specified for this user, as the argument of ftp PASS command
        :param homedir: the initial directory when user logged in
        :param perm: check permission when user modify directory
        :param msg_login: customized response string when user logged in
        :param msg_quit: customized response string when user quit

        Read permissions:
         - "e" = change directory (CWD command)
         - "l" = list files (LIST, NLST, STAT, MLSD, MLST, SIZE, MDTM commands)
         - "r" = retrieve file from the server (RETR command)

        Write permissions:
         - "a" = append data to an existing file (APPE command)
         - "d" = delete file or directory (DELE, RMD commands)
         - "f" = rename file or directory (RNFR, RNTO commands)
         - "m" = create directory (MKD command)
         - "w" = store a file to the server (STOR, STOU commands)
         - "M" = change file mode (SITE CHMOD command)
         - "T" = update file last modified time (MFMT command)
        """
        raise NotImplementedError

    def add_anonymous(self, homedir, **kwargs):
        """Add an anonymous user."""
        self.add_user('anonymous', '', homedir, **kwargs)

    def remove_user(self, username: str):
        """Remove a user."""
        raise NotImplementedError

    async def override_perm(self, username: str, directory: str, perm: str, recursive=False):
        """Override permissions for a given directory."""
        raise NotImplementedError

    async def validate_authentication(self, username: str, password: str, handler: 'FTPHandler'):
        """
        Raises AuthenticationFailed if supplied username and password
        don't match, else return None
        """
        raise NotImplementedError

    async def get_home_dir(self, username: str):
        """Return the user's homedir."""
        raise NotImplementedError

    async def has_user(self, username: str) -> bool:
        """To check whether the username specified exists."""
        raise NotImplementedError

    async def has_perm(self, username: str, perm: str, path: str = None):
        """
        Whether the user has permission over path.
        Expected perm argument is one of the following letters: "elradfmwMT".
        """
        raise NotImplementedError

    async def get_perms(self, username: str):
        """Return current user permissions."""
        raise NotImplementedError

    async def get_msg_login(self, username):
        """Return the user's login message."""
        raise NotImplementedError

    async def get_msg_quit(self, username: str):
        """Return the user's quitting message."""

    def __new__(cls, *args, **kwargs):
        if not cls._single_instance:
            cls._single_instance = super(AbstractAuthorizer, cls).__new__(cls, *args, **kwargs)
        return cls._single_instance


class DummyAuthorizer(AbstractAuthorizer):
    read_perms = "elr"
    write_perms = "adfmwMT"

    def __init__(self):
        self.user_table = {}

    def add_user(self, username: str, password: str, homedir: str,
                 perm='elr', msg_login: str = 'Login successful', msg_quit: str = 'GoodBye'):
        if self.has_user(username):
            raise ValueError('user %r already exists' % username)
        if not os.path.isdir(homedir):
            raise ValueError("no such directory: %r" % homedir)
        homedir = os.path.realpath(homedir)
        self._check_permissions(username, perm)
        dic = {
            'pwd': str(password),
            'home': homedir,
            'perm': perm,
            'operms': {},
            'msg_login': str(msg_login),
            'msg_quit': str(msg_quit)
        }
        self.user_table[username] = dic

    def has_user(self, username: str) -> bool:
        return username in self.user_table

    def remove_user(self, username) -> None:
        del self.user_table[username]

    async def override_perm(self, username: str, directory: str, perm: str, recursive: bool = False) -> None:
        self._check_permissions(username, perm)
        if not os.path.isdir(directory):
            raise ValueError("no such directory: %r" % directory)
        directory = os.path.normcase(os.path.realpath(directory))
        home = os.path.normcase(await self.get_home_dir(username))
        if directory == home:
            raise ValueError("can't override home directory permissions")
        if not self._issubpath(directory, home):
            raise ValueError("path escapes user home directory")
        self.user_table[username]['operms'][directory] = perm, recursive

    async def validate_authentication(self, username: str, password: str, handler: 'FTPHandler') -> None:
        msg = "Authentication failed."
        if not self.has_user(username):
            if username == 'anonymous':
                msg = "Anonymous access not allowed."
                raise AuthenticationFailed(msg)
        if username != 'anonymous':
            if self.user_table[username]['pwd'] != password:
                raise AuthenticationFailed(msg)

    async def get_home_dir(self, username: str) -> str:
        return self.user_table[username]['home']

    async def has_perm(self, username: str, perm: str, path: Union[str, None] = None) -> bool:
        if path is None:
            return perm in self.user_table[username]['perm']
        path = os.path.normcase(path)
        for dir in self.user_table[username]['operms'].keys():
            operm, recursive = self.user_table[username]['operms'][dir]
            if self._issubpath(path, dir):
                if recursive:
                    return perm in operm
                if path == dir or os.path.dirname(path) == dir and not os.path.isdir(path):
                    return perm in operm
        return perm in self.user_table[username]['perm']

    async def get_perms(self, username: str) -> str:
        return self.user_table[username]['perm']

    async def get_msg_login(self, username: str) -> str:
        return self.user_table[username]['msg_login']

    async def get_msg_quit(self, username: str) -> str:
        try:
            return self.user_table[username]['msg_quit']
        except KeyError:
            return "Goodbye."

    def _check_permissions(self, username: str, perm: str):
        warned = 0
        for p in perm:
            if p not in self.read_perms + self.write_perms:
                raise ValueError("no such permission %r" % p)
            if (username == 'anonymous' and
                    p in self.write_perms and not warned):
                warnings.warn("write permissions assigned to anonymous user.", RuntimeWarning)
            warned += 1

    def _issubpath(self, a: str, b: str) -> bool:
        p1 = a.strip(os.sep).split(os.sep)
        p2 = b.strip(os.sep).split(os.sep)
        return p1[:len(p2)] == p2
