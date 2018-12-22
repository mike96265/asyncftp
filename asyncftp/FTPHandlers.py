import glob
import logging
import os
import socket
import sys
import time
from asyncio import Protocol, Transport, AbstractEventLoop, StreamWriter, StreamReader
from typing import Union, Tuple, TYPE_CHECKING

from .Authorizer import AuthenticationFailed, AuthorizerError, DummyAuthorizer, AbstractAuthorizer
from .Filesystems import AbstractFilesystem, FilesystemError
from .DTP import ActiveDTP, PassiveDTP

if TYPE_CHECKING:
    from .Servers import AbstractServer

from . import __ver__

__all__ = ['FTPHandler']

_proto_cmds = {
    'ABOR': dict(
        perm=None, auth=True, arg=False,
        help='Syntax: ABOR (abort transfer).'),
    'ALLO': dict(
        perm=None, auth=True, arg=True,
        help='Syntax: ALLO <SP> bytes (noop; allocate storage).'),
    'APPE': dict(
        perm='a', auth=True, arg=True,
        help='Syntax: APPE <SP> file-name (append data to file).'),
    'CDUP': dict(
        perm='e', auth=True, arg=False,
        help='Syntax: CDUP (go to parent directory).'),
    'CWD': dict(
        perm='e', auth=True, arg=None,
        help='Syntax: CWD [<SP> dir-name] (change working directory).'),
    'DELE': dict(
        perm='d', auth=True, arg=True,
        help='Syntax: DELE <SP> file-name (delete file).'),
    'EPRT': dict(
        perm=None, auth=True, arg=True,
        help='Syntax: EPRT <SP> |proto|ip|port| (extended active mode).'),
    'EPSV': dict(
        perm=None, auth=True, arg=None,
        help='Syntax: EPSV [<SP> proto/"ALL"] (extended passive mode).'),
    'FEAT': dict(
        perm=None, auth=False, arg=False,
        help='Syntax: FEAT (list all new features supported).'),
    'HELP': dict(
        perm=None, auth=False, arg=None,
        help='Syntax: HELP [<SP> cmd] (show help).'),
    'LIST': dict(
        perm='l', auth=True, arg=None,
        help='Syntax: LIST [<SP> path] (list files).'),
    'MDTM': dict(
        perm='l', auth=True, arg=True,
        help='Syntax: MDTM [<SP> path] (file last modification time).'),
    'MFMT': dict(
        perm='T', auth=True, arg=True,
        help='Syntax: MFMT <SP> timeval <SP> path (file update last '
             'modification time).'),
    'MLSD': dict(
        perm='l', auth=True, arg=None,
        help='Syntax: MLSD [<SP> path] (list directory).'),
    'MLST': dict(
        perm='l', auth=True, arg=None,
        help='Syntax: MLST [<SP> path] (show information about path).'),
    'MODE': dict(
        perm=None, auth=True, arg=True,
        help='Syntax: MODE <SP> mode (noop; set data transfer mode).'),
    'MKD': dict(
        perm='m', auth=True, arg=True,
        help='Syntax: MKD <SP> path (create directory).'),
    'NLST': dict(
        perm='l', auth=True, arg=None,
        help='Syntax: NLST [<SP> path] (list path in a compact form).'),
    'NOOP': dict(
        perm=None, auth=False, arg=False,
        help='Syntax: NOOP (just do nothing).'),
    'OPTS': dict(
        perm=None, auth=True, arg=True,
        help='Syntax: OPTS <SP> cmd [<SP> option] (set option for command).'),
    'PASS': dict(
        perm=None, auth=False, arg=True,
        help='Syntax: PASS [<SP> password] (set user password).'),
    'PASV': dict(
        perm=None, auth=True, arg=False,
        help='Syntax: PASV (open passive data connection).'),
    'PORT': dict(
        perm=None, auth=True, arg=True,
        help='Syntax: PORT <sp> h,h,h,h,p,p (open active data connection).'),
    'PWD': dict(
        perm=None, auth=True, arg=False,
        help='Syntax: PWD (get current working directory).'),
    'QUIT': dict(
        perm=None, auth=False, arg=False,
        help='Syntax: QUIT (quit current session).'),
    'REIN': dict(
        perm=None, auth=True, arg=False,
        help='Syntax: REIN (flush account).'),
    'REST': dict(
        perm=None, auth=True, arg=True,
        help='Syntax: REST <SP> offset (set file offset).'),
    'RETR': dict(
        perm='r', auth=True, arg=True,
        help='Syntax: RETR <SP> file-name (retrieve a file).'),
    'RMD': dict(
        perm='d', auth=True, arg=True,
        help='Syntax: RMD <SP> dir-name (remove directory).'),
    'RNFR': dict(
        perm='f', auth=True, arg=True,
        help='Syntax: RNFR <SP> file-name (rename (source name)).'),
    'RNTO': dict(
        perm='f', auth=True, arg=True,
        help='Syntax: RNTO <SP> file-name (rename (destination name)).'),
    'SITE': dict(
        perm=None, auth=False, arg=True,
        help='Syntax: SITE <SP> site-command (execute SITE command).'),
    'SITE HELP': dict(
        perm=None, auth=False, arg=None,
        help='Syntax: SITE HELP [<SP> cmd] (show SITE command help).'),
    'SITE CHMOD': dict(
        perm='M', auth=True, arg=True,
        help='Syntax: SITE CHMOD <SP> mode path (change file mode).'),
    'SIZE': dict(
        perm='l', auth=True, arg=True,
        help='Syntax: SIZE <SP> file-name (get file size).'),
    'STAT': dict(
        perm='l', auth=False, arg=None,
        help='Syntax: STAT [<SP> path name] (server stats [list files]).'),
    'STOR': dict(
        perm='w', auth=True, arg=True,
        help='Syntax: STOR <SP> file-name (store a file).'),
    'STOU': dict(
        perm='w', auth=True, arg=None,
        help='Syntax: STOU [<SP> name] (store a file with a unique name).'),
    'STRU': dict(
        perm=None, auth=True, arg=True,
        help='Syntax: STRU <SP> type (noop; set file structure).'),
    'SYST': dict(
        perm=None, auth=False, arg=False,
        help='Syntax: SYST (get operating system type).'),
    'TYPE': dict(
        perm=None, auth=True, arg=True,
        help='Syntax: TYPE <SP> [A | I] (set transfer type).'),
    'USER': dict(
        perm=None, auth=False, arg=True,
        help='Syntax: USER <SP> user-name (set username).'),
    'XCUP': dict(
        perm='e', auth=True, arg=False,
        help='Syntax: XCUP (obsolete; go to parent directory).'),
    'XCWD': dict(
        perm='e', auth=True, arg=None,
        help='Syntax: XCWD [<SP> dir-name] (obsolete; change directory).'),
    'XMKD': dict(
        perm='m', auth=True, arg=True,
        help='Syntax: XMKD <SP> dir-name (obsolete; create directory).'),
    'XPWD': dict(
        perm=None, auth=True, arg=False,
        help='Syntax: XPWD (obsolete; get current dir).'),
    'XRMD': dict(
        perm='d', auth=True, arg=True,
        help='Syntax: XRMD <SP> dir-name (obsolete; remove directory).'),
}

logger = logging.getLogger("asyncio")
logger.setLevel(logging.DEBUG)


class _FileReadWriteError(OSError):
    """
    Exception raised when reading or writing a file during a transfer.
    """


class _GiveUpOnSendfile(Exception):
    """
    Exception raised in case of use of sendfile() fails on first try,
    in which case send will be used
    """


class FTPHandler:
    # default attribute
    authorizer = DummyAuthorizer()
    active_dtp = ActiveDTP
    passive_dtp = PassiveDTP
    abstracted_fs = AbstractFilesystem
    proto_cmds = _proto_cmds
    log_cmds_list = ["DELE", "RNFR", "RNTO", "MKD", "RMD", "CWD",
                     "XMKD", "XRMD", "XCWD",
                     "REIN", "SITE CHMOD", "MFMT"]

    # session attributes
    _current_type = 'a'
    timeout = 300
    banner = "AsyncFtp %s ready." % __ver__
    max_login_attempts = 3

    permit_foreign_addresses = False
    permit_privileged_ports = False
    masquerade_address = None
    masquerade_address_map = {}

    passive_ports = None
    use_gmt_times = True
    use_sendfile = True
    tcp_no_delay = hasattr(socket, 'TCP_NODELAY')

    encoding = 'utf8'
    log_prefix_template = '%(remote_host)s:%(remote_port)s-[%(username)s]'

    @classmethod
    def set_authorizer(cls, authorizer):
        cls.authorizer = authorizer

    @classmethod
    def set_active_dtp(cls, active_dtp):
        cls.active_dtp = active_dtp

    def __init__(
            self,
            remote_host: str,
            remote_port: int,
            server: 'AbstractServer',
            loop: AbstractEventLoop,
            reader: StreamReader,
            writer: StreamWriter
    ):
        # remote attributes
        self.remote_host = remote_host
        self.remote_port = remote_port

        # server attributes
        self.server = server
        self.loop = loop

        # command channel attributes
        self.reader = reader
        self.writer = writer

        # data channel
        self.data_channel = None

        # user-associate attributes
        self.username = ''
        self.authenticated = False
        self.attempted_login_times = 0
        self.fs: AbstractFilesystem = None

        # other
        self._log_debug = logging.getLogger(__name__).getEffectiveLevel() <= logging.DEBUG
        self._last_response = None
        self._closing = False
        self._closed = False

    async def handle(self):
        await self.on_connect()
        while True:
            try:
                line, cmd, arg = await self.parse_command()
                valid, *args = self.validate_cmd(line, cmd, arg)
                if not valid:
                    cmd, arg, code, msg = args
                    self.log_cmd(cmd, arg, code, arg)
                    await self.respond(code, msg)
                else:
                    cmd, arg, kwargs = args
                    await self.process_cmd(cmd, arg, **kwargs)
            except Exception as err:
                print(err)

    async def on_connect(self):
        if len(self.banner) <= 75:
            await self.respond(220, self.banner)
        else:
            await self.push("220-%s\r\n" % self.banner)
            await self.respond(220)

    async def on_login_failed(self, username: str, password: str):
        pass

    async def on_login(self, username: str):
        pass

    async def process_cmd(self, cmd, arg, **kwargs):
        method = getattr(self, 'ftp_%s' % cmd)
        await method(arg, **kwargs)

    def validate_cmd(self, line: str, cmd: str, arg: str) -> \
            Union[Tuple[bool, str, str, int, str], Tuple[bool, str, str, dict]]:
        kwargs = {}
        if cmd == "SITE" and arg:
            cmd = "SITE %s" % arg.split(' ')[0].upper()
            arg = line[len(cmd) + 1:]

        if cmd != 'PASS':
            self.logline("<- %s" % line)
        else:
            self.logline("<- %s %s" % (cmd, '*' * 6))

        if cmd not in self.proto_cmds:
            if cmd[-4:] in ('ABOR', 'STAT', 'QUIT'):
                cmd = cmd[-4:]
            else:
                msg = 'Command "%s" not understand.' % cmd
                return False, cmd, arg, 500, msg
        if not arg and self.proto_cmds[cmd]['arg'] is True:
            msg = "Syntax error: command needs argument."
            return False, cmd, "", 501, msg

        if arg and self.proto_cmds[cmd]['arg'] is False:
            msg = "Syntax error: command does not accept arguments."
            return False, cmd, arg, 501, msg

        if not self.authenticated:
            if self.proto_cmds[cmd]['auth'] or (cmd == 'STAT' and arg):
                msg = "Log in with the USER and PASS first."
                return False, cmd, arg, 530, msg
            else:
                return True, cmd, arg, {}
        else:
            if (cmd == 'STAT') and not arg:
                return True, 'STAT', '', {}
            if self.proto_cmds[cmd]['perm'] and (cmd != 'STOU'):
                if cmd in ('CWD', 'XCWD'):
                    arg = self.fs.ftp2fs(arg or '/')
                elif cmd in ('CDUP', 'XDUP'):
                    arg = self.fs.ftp2fs('..')
                elif cmd == 'LIST':
                    if arg.lower() in ('-a', '-l', '-al', 'la'):
                        arg = self.fs.ftp2fs(self.fs.cwd)
                    else:
                        arg = self.fs.ftp2fs(arg or self.fs.cwd)
                elif cmd == 'STAT':
                    if glob.has_magic(arg):
                        msg = "Globing not supported."
                        return False, cmd, arg, 500, msg
                    arg = self.fs.ftp2fs(arg or self.fs.cwd)
                elif cmd == 'SITE CHMOD':
                    if ' ' not in arg:
                        msg = "Syntax error: command need two arguments."
                        return False, cmd, "", 501, msg
                    else:
                        timeval, arg = arg.split(' ', 1)
                        arg = self.fs.ftp2fs(arg)
                        kwargs = dict(timeval=timeval)
                else:
                    line = self.fs.ftp2fs(arg)
                    msg = "'%s' points to path witch is outside " \
                          "the user's root directory" % line
                    return False, cmd, arg, 550, msg

                perm = self.proto_cmds[cmd]['perm']
                if perm is not None and cmd != 'STOU':
                    if not self.authorizer.has_perm(self.username, perm, arg):
                        msg = "Not enough privileges."
                        return False, cmd, arg, 550, msg
                return True, cmd, arg, kwargs

    def log_cmd(self, cmd: str, arg: str, respcode: int, respstr: str):
        if not self._log_debug and cmd in self.log_cmds_list:
            line = '%s %s' % (' '.join([cmd, arg]).strip(), respcode)
            if str(respcode)[0] in ('4', '5'):
                line += ' %r' % respstr
            self.log(line)

    async def parse_command(self) -> Tuple[str, str, str]:
        line = (await self.reader.readline()).decode(self.encoding).rstrip()
        cmd = line.split(' ')[0].upper()
        arg = line[len(cmd) + 1:]
        return line, cmd, arg

    async def handle_max_cons(self):
        pass

    async def handle_max_cons_per_ip(self):
        pass

    async def push(self, s: str):
        self.writer.write(s.encode(self.encoding))
        await self.writer.drain()

    async def respond(self, code: int, msg: str = '', logfun=logger.debug):
        resp = '%d %s' % (code, msg)
        self._last_response = resp
        await self.push(resp + '\r\n')
        if self._log_debug:
            self.logline('-> %s' % resp, logfun=logfun)
        else:
            self.log(resp[4:], logfun=logfun)

    def log(self, msg: str, logfun=logger.info):
        """
        Log a msg including additional identifying session data.
        By default this is disable unless logging level == DEBUG
        """
        logfun('%s %s' % (self.log_prefix, msg))

    def logline(self, msg: str, logfun=logger.debug):
        if self._log_debug:
            logfun('%s %s' % (self.log_prefix, msg))

    def logerror(self, msg: str):
        logger.error(self.log_prefix, msg)

    def log_exception(self, instance):
        logger.exception("Unhandled exception in instance %r", instance)

    @property
    def log_prefix(self):
        return self.log_prefix_template % self.__dict__

    # identification command

    async def ftp_USER(self, username: str):
        if not self.authenticated:
            await self.respond(331, "Username ok, send password")
            self.username = username
        else:
            await self.flush_account()
            msg = "Previous account information was flushed, send password"
            await self.respond(331, msg, logfun=logger.info)

    async def ftp_PASS(self, password: str):
        if self.authenticated:
            await self.respond(503, "User already authenticated.")
            return
        if not self.username:
            await self.respond(503, "Login with USER first.")
            return

        try:
            await self.authorizer.validate_authentication(self.username, password, self)
            home = await self.authorizer.get_home_dir(self.username)
            msg_login = await self.authorizer.get_msg_login(self.username)
        except(AuthenticationFailed, AuthorizerError) as err:
            await self.handle_auth_failed(str(err), password)
        else:
            await self.handle_auth_success(home, password, msg_login)

    async def flush_account(self):
        pass

    async def handle_auth_failed(self, msg: str, password: str):
        if not msg:
            if self.username == 'anonymous':
                msg = 'Anonymous access not allowed.'
            else:
                msg = 'Authentication failed.'
        else:
            msg = msg.capitalize()
        self.attempted_login_times += 1
        if self.attempted_login_times >= self.max_login_attempts:
            msg += " Disconnecting."
            await self.respond(530, msg)
        else:
            await self.respond(530, msg)
        self.log("USER '%s' failed login." % self.username)
        await self.on_login_failed(self.username, password)
        self.username = ""

    async def handle_auth_success(self, home, password, msg_login):
        if len(msg_login) <= 75:
            await self.respond(230, msg_login)
        else:
            await self.push('230-%s' % msg_login)
            await self.respond(230)
        self.log("USER '%s' logged in." % self.username)
        self.authenticated = True
        self.attempted_login_times = 0
        self.fs = self.abstracted_fs(home, self)
        await self.on_login(self.username)

    async def ftp_REIN(self, arg):
        """Reinitialize user's current session"""
        await self.flush_account()
        await self.respond(230, "Ready for new user.")

    async def ftp_CWD(self):
        pass

    # file action commands

    async def ftp_ALLO(self, line):
        await self.respond(202, "No storage allocation necessary")

    async def ftp_ABOR(self, line):
        pass

    async def ftp_PWD(self, line):
        cwd = self.fs.cwd
        await self.respond(257, "%s is the current directory." % cwd.replace('"', '""'))

    async def ftp_REST(self, line):
        """Restart a file transfer from a previous mark."""
        if self._current_type == 'a':
            await self.respond(501, )
            return
        try:
            marker = int(line)
            if marker < 0:
                raise ValueError
        except (ValueError, OverflowError) as err:
            await self.respond(501, "Invalid paramter")
        else:
            await self.respond(350, "Restarting at position %s." % marker)
            self._restart_position = marker

    async def ftp_STOR(self, file, mode='w'):
        """
        Store a file (transfer from the client to the server).
        On success return the file path, else None.
        """
        if 'a' in mode:
            cmd = 'APPE'
        else:
            cmd = 'STOR'
        rest_pos = self._restart_position
        self._restart_position = 0
        if rest_pos:
            mode = 'r+'
        try:
            fd = self.fs.open(file, mode + 'b')
        except (EnvironmentError, FilesystemError) as err:
            why = str(err)
            await self.respond(550, "%s." % why)
            return
        try:
            if rest_pos:
                ok = 0
                try:
                    if rest_pos > self.fs.getsize(file):
                        raise ValueError
                    fd.seek(rest_pos)
                    ok = 1
                except ValueError:
                    why = "Invalid REST parameter"
                except (EnvironmentError, FilesystemError) as err:
                    why = str(err)
                if not ok:
                    fd.close()
                    await self.respond(554, '%s' % why)
                    return
            if self.data_channel is not None:
                resp = "Data connection already open. Transfer starting."
                await self.respond(125, resp)
                self.data_channel.file_obj = fd
                self.data_channel.enable_receiving(self._current_type, cmd)
            else:
                resp = "File status okay, About to open data connection."
                await self.respond(150, resp)
                self._in_dtp_queue = (fd, cmd)
            return file
        except Exception:
            fd.close()
            raise

    async def ftp_STOU(self, line):
        """
        Store a file on the server with a unique name.
        On success return the file path, else None.
        """
        if self._restart_position:
            await self.respond(450, "Can't STOU while REST request is pending.")
            return
        if line:
            basedir, prefix = os.path.split(self.fs.ftp2fs(line))
            prefix = prefix + '.'
        else:
            basedir = self.fs.ftp2fs(self.fs.cwd)
            prefix = 'ftpd.'

    async def ftp_APPE(self, file):
        """
        Append data to an existing file on the server.
        On success return the file path,else None
        """
        if self._restart_position:
            await self.respond(450, "Can't APPE while REST request is pending.")
        else:
            return await self.ftp_STOR(file, mode='a')

    # information commands

    async def ftp_SYST(self, line):
        await self.respond(215, "UNIX Type: L8")

    # Miscellaneous commands

    async def ftp_STAT(self, line):
        pass

    async def ftp_NOOP(self, line):
        """Do nothing"""
        await self.respond(200, "I successfully done nothing.")


def find_prefix_at_end(haystack, needle):
    length = len(needle) - 1
    while length and not haystack.endswith(needle[:length]):
        length -= 1
    return length
