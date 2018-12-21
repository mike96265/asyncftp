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
from .dtp import ActiveDTP, PassiveDTP

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
                    arg = self.fs.ftp2fs(arg, self.fs.cwd)
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

    async def ftp_NOOP(self, line):
        """Do nothing"""
        await self.respond(200, "I successfully done nothing.")

class __FTPHandler(Protocol):
    # default classes
    authorizer = DummyAuthorizer()
    active_dtp = ActiveDTP
    passive_dtp = PassiveDTP
    abstracted_fs = AbstractFilesystem
    # proto_cmds = proto_cmds

    # session attributes
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

    log_prefix = '%(remote_ip)s:%(remote_port)s-[%(username)s]'
    terminator = b'\r\n'
    use_encoding = 0
    encoding = 'utf8'
    auth_failed_timeout = 3

    def __init__(self, loop: AbstractEventLoop):

        # public session attributes
        self.loop = loop
        self.transport: Transport = None
        self.fs: AbstractFilesystem = None
        self.authenticated = False
        self.username = ''
        self.password = ''
        self.attempted_login_times = 0
        self.remote_ip = 'unknown'
        self.remote_port = -1
        self.start_time = time.time()

        self._last_response = ""
        self._current_type = 'a'
        self._restart_position = 0
        self._quit_pending = False
        self._in_buffer = []
        self._in_buffer_len = 0
        self._epsvall = False
        self._dtp_protocol = None
        self._closed = False
        self._closing = False
        self._log_debug = logging.getLogger('asyncio').getEffectiveLevel() <= logging.DEBUG
        self.set_terminator(b"\r\n")
        self.data_channel = None

        self.ac_in_buffer = b''

    def connection_made(self, transport: Transport):
        self.transport = transport
        self.loop.create_task(self.handle())

    def data_received(self, data: bytes):
        self.ac_in_buffer += data
        lb = len(self.ac_in_buffer)
        terminator = self.get_terminator()
        terminator_len = len(terminator)
        while self.ac_in_buffer:
            index = self.ac_in_buffer.find(terminator)
            if index != -1:
                if index > 0:
                    self._collect_incoming_data(self.ac_in_buffer[:index])
                    self.ac_in_buffer = self.ac_in_buffer[index + terminator_len:]
                    self.found_terminator()
            else:
                index = find_prefix_at_end(self.ac_in_buffer, terminator)
                if index:
                    if index != lb:
                        self.collect_incoming_data(self.ac_in_buffer[:-index])
                        self.ac_in_buffer = self.ac_in_buffer[-index:]
                else:
                    self.collect_incoming_data(self.ac_in_buffer)
                    self.ac_in_buffer = b''

    def close(self):
        self.transport.close()

    async def collect_incoming_data(self, data):
        self._in_buffer.append(data)
        self._in_buffer_len += len(data)
        buf_limit = 2048
        if self._in_buffer_len > buf_limit:
            async def command_too_long():
                async with self.cmd_lock:
                    await self.respond_w_waring('500 Command too long.')

    def _collect_incoming_data(self, data: str):
        """Read incoming data and append to the input buffer"""
        self._in_buffer.append(data)
        self._in_buffer_len += len(data)
        buflimit = 2048
        if self._in_buffer_len > buflimit:
            self.respond_w_waring('500 Command too long.')
            self._in_buffer = []
            self._in_buffer_len = 0

    def found_terminator(self):
        # if not self._idler is not None and not self._idler_canceled:
        #     self._idler.reset()
        line = b''.join(self._in_buffer)
        try:
            line = self.decode(line)
        except UnicodeDecodeError:
            self.loop.create_task(self.respond("Can't decode command"))
        self._in_buffer = []
        self._in_buffer_len = 0
        cmd = line.split(' ')[0].upper()
        arg = line[len(cmd) + 1:]
        try:
            self.pre_process_cmd(line, cmd, arg)
        except UnicodeEncodeError:
            self.loop.create_task(self.respond("501 can't decode path (server file system encoding"
                                               "is %s)" % sys.getfilesystemencoding()))

    def pre_process_cmd(self, line: str, cmd: str, arg: str):
        kwargs = {}
        if cmd == "SITE" and arg:
            cmd = "SITE %s" % arg.split(' ')[0].upper()
            arg = line[len(cmd) + 1:]
        if cmd != 'PASS':
            self.logline("< - %s" % line)
        else:
            self.logline("<- %s %s" % (line.split(' ')[0], '*' * 6))

        if cmd not in self.proto_cmds:
            if cmd[-4:] in ('ABOR', 'STAT', 'QUIT'):
                cmd = cmd[-4:]
            else:
                msg = 'Command "%s" not understand.' % cmd
                self.loop.create_task(self.respond('500 ' + msg))
                return

        if not arg and self.proto_cmds[cmd]['arg']:
            msg = "Syntax error: command needs argument."
            self.loop.create_task(self.respond('501 ' + msg))
            self.log_cmd(cmd, "", 501, msg)
            return

        if arg and not self.proto_cmds[cmd]['arg']:
            msg = "Syntax error: command does not accept arguments."
            self.loop.create_task(self.respond("501 " + msg))
            self.log_cmd(cmd, arg, 501, msg)
            return

        if not self.authenticated:
            if self.proto_cmds[cmd]['auth'] or (cmd == 'STAT' and arg):
                msg = "Log in with the USER and PASS first."
                self.loop.create_task(self.respond("530 " + msg))
                self.log_cmd(cmd, arg, 530, msg)
            else:
                self.process_command(cmd, arg)
                return
        else:
            if (cmd == 'STAT') and not arg:
                self.loop.create_task(self.ftp_STAT(u''))
                return
            if self.proto_cmds[cmd]['perm'] and (cmd != 'STOU'):
                if cmd in ('CWD', 'XCWD'):
                    arg = self.fs.ftp2fs(arg or '/')
                elif cmd in ('CDUP', 'XDUP'):
                    arg = self.fs.ftp2fs('..')
                elif cmd == 'LIST':
                    if arg.lower() in ('-a', '-l', '-al', '-la'):
                        arg = self.fs.ftp2fs(self.fs.cwd)
                    else:
                        arg = self.fs.ftp2fs(arg or self.fs.cwd)
                elif cmd == 'STAT':
                    if glob.has_magic(arg):
                        msg = 'Globbing not supported'
                        self.loop.create_task(self.respond('550 ' + msg))
                        self.log_cmd(cmd, arg, 500, msg)
                        return
                    arg = self.fs.ftp2fs(arg, self.fs.cwd)
                elif cmd == 'SITE CHMOD':
                    if ' ' not in arg:
                        msg = "Syntax error: command needs two arguments."
                        self.respond("501 " + msg)
                        self.log_cmd(cmd, "", 501, msg)
                        return
                    else:
                        timeval, arg = arg.split(' ', 1)
                        arg = self.fs.ftp2fs(arg)
                        kwargs = dict(timeval=timeval)
                else:
                    line = self.fs.fs2ftp(arg)
                    msg = "'%s' points to path which is outside " \
                          "the user's root directory" % line
                    self.loop.create_task(self.respond("500 %s." % msg))
                    self.log_cmd(cmd, arg, 550, msg)
                    return

            perm = self.proto_cmds[cmd]['perm']
            if perm is not None and cmd != 'STOU':
                if not self.authorizer.has_perm(self.username, perm, arg):
                    msg = "Not enough privileges."
                    self.loop.create_task(self.respond("550 " + msg))
                    self.log_cmd(cmd, arg, 550, msg)
                    return
            self.process_command(cmd, arg, **kwargs)

    def process_command(self, cmd, *args, **kwargs):
        if self._closed:
            return
        self._last_response = ""
        method = getattr(self, 'ftp_' + cmd.replace(' ', '_'))
        method(*args, **kwargs)
        if self._last_response:
            code = int(self._last_response[:3])
            resp = self._last_response[4:]
            self.log_cmd(cmd, args[0], code, resp)

    def set_terminator(self, term):
        """Set the input delimiter.

        Can be a fixed string of any length, an integer, or None.
        """
        if isinstance(term, str) and self.use_encoding:
            term = bytes(term, self.encoding)
        elif isinstance(term, int) and term < 0:
            raise ValueError('the number of received bytes must be positive')
        self.terminator = term

    def get_terminator(self):
        return self.terminator

    async def handle(self):
        self.on_connect()
        if not self._closed and not self._closing:
            if len(self.banner) <= 75:
                await self.respond("220 %s" % self.banner)
            else:
                await self.push("220-%s\r\n" % self.banner)
                await self.respond("200 ")

    async def handle_max_cons(self):
        """Called when limit for maximum number if connections is reached."""
        msg = "421 Too many connections. Service temporarily unavailable"
        await self.respond_w_waring(msg)
        self.transport.close()

    def handle_max_cons_per_ip(self):
        """Called when too many clients are connected from the same ip"""
        msg = "421 Too many connections from the same ip address."
        self.loop.create_task(self.respond_w_waring(msg))
        self.close()

    async def handle_timeout(self):
        """Called when client does not send any command within the time specified
        in <timeout> attribute"""

    def decode(self, data: bytes):
        return data.decode('utf8')

    def on_connect(self):
        """
        called when connection is closed
        :return:
        """

    async def push(self, s: str) -> None:
        await self.loop.sock_sendall(self.transport.get_extra_info('socket'), s.encode('utf8'))

    async def respond(self, resp: str, logfun=logger.debug):
        """
        send a response to the client
        :param resp: server response
        :param logfun: func to logger runtime info
        :return:
        """
        self._last_response = resp
        await self.push(resp + '\r\n')
        if self._log_debug:
            self.logline('-> %s' % resp, logfun=logfun)
        else:
            self.log(resp[4:], logfun=logfun)

    async def respond_w_waring(self, resp):
        await self.respond(resp, logger.warning)

    def log(self, msg: str, logfun=logger.info):
        """
        Log a msg including additional identifying session data.
        By default this is disable unless logging level == DEBUG
        """
        logfun('%s %s' % (self.msg_prefix, msg))

    def logline(self, msg: str, logfun=logger.debug):
        if self._log_debug:
            logfun('%s %s' % (self.msg_prefix, msg))

    def logerror(self, msg: str):
        logger.error(self.msg_prefix, msg)

    def log_exception(self, instance):
        logger.exception("Unhandled exception in instance %r", instance)

    @property
    def msg_prefix(self):
        return self.log_prefix % self.__dict__

    log_cmds_list = ["DELE", "RNFR", "RNTO", "MKD", "RMD", "CWD",
                     "XMKD", "XRMD", "XCWD",
                     "REIN", "SITE CHMOD", "MFMT"]

    def log_cmd(self, cmd: str, arg: str, resp_code: Union[str, int], resp_str: str):
        if not self._log_debug and cmd in self.log_cmds_list:
            line = '%s %s' % (' '.join([cmd, arg]).strip(), resp_str)
            if str(resp_code)[0] in ('4', '5'):
                line += resp_str
            self.log(line)

    def log_transfer(self, cmd: str, filename: str, receive: bool, completed: bool, elapsed: float, size: int):
        line = '%s %s receive=%s completed=%s size=%s seconds=%s' % \
               (cmd, filename, receive and 1 or 0, completed and 1 or 0, size, elapsed)
        self.log(line)

    #
    # def ftp_PORT(self, line: str):
    #     """
    #     Start an active data channel by using ipv4
    #     """
    #     if self._epsvall:
    #         self.respond("501 PORT not allowed after EPSV ALL")
    #         return
    #     try:
    #         addr = list(map(int, line.split(',')))
    #         if len(addr) != 6:
    #             raise ValueError("")
    #         for x in addr[:4]:
    #             if not 0 <= x <= 256:
    #                 raise ValueError("")
    #         ip = '{}.{}.{}.{}'.format(*addr[:4])
    #         port = (addr[4] * 256) + addr[5]
    #         if not 0 <= port <= 65535:
    #             raise ValueError("")
    #     except (ValueError, OverflowError):
    #         self.respond("501 Invalid PORT format")
    #         return
    #     self._make_eport(ip, port)

    """
    Deal with client authentication
    """

    async def ftp_USER(self, line):
        if not self.authenticated:
            await self.respond("331 Username ok, send password")
        else:
            self.flush_account()
            msg = "Previous account information was flushed"
            await self.respond('331 %s, send password' % msg, logfun=logger.info)
        self.username = line

    async def ftp_PASS(self, line):
        if self.authenticated:
            await self.respond("503 User already authenticated.")
            return
        if not self.username:
            await self.respond("503 Login with User first")
            return
        try:
            self.authorizer.validate_authentication(self.username, line, self)
            home = self.authorizer.get_home_dir(self.username)
            msg_login = self.authorizer.get_msg_login(self.username)
        except (AuthenticationFailed, AuthorizerError) as err:
            await self.handle_auth_failed(str(err), line)
        else:
            await self.handle_auth_success(home, line, msg_login)

    def flush_account(self):
        """Flush account information by clearing attributes that need
        to be reset on a REIN or new USER command.
        """
        self._shutdown_connecting_dtp()
        # if there's a transfer in progress RFC-959 states we are
        # supposed to let it finish
        if self.data_channel is not None:
            if not self.data_channel.transfer_in_progress():
                self.data_channel.close()
                self.data_channel = None

        username = self.username
        if self.authenticated and username:
            self.on_logout(username)
        self.authenticated = False
        self.username = ""
        self.password = ""
        self.attempted_login_times = 0
        self._current_type = 'a'
        self._restart_position = 0
        self._quit_pending = False
        self._in_dtp_queue = None
        self._rnfr = None
        self._out_dtp_queue = None

    async def handle_auth_failed(self, msg, password):
        def callback(_username, _password, _msg):
            if hasattr(self, '_closed') and not self._closed:
                self.attempted_login_times += 1
                if self.attempted_login_times > self.max_login_attempts:
                    _msg += "Disconnecting."
                    self.loop.create_task(self.respond("530 " + _msg))
                    self.close()
                else:
                    self.respond("530 " + _msg)
                self.log("USER '%s' failed login" % _username)
            self.on_login_failed(_username, _password)

        if not msg:
            if self.username == 'anonymous':
                msg = "Anonymous access not allowed."
            else:
                msg = "Authentication failed."
        else:
            msg = msg.capitalize()
        self.loop.call_later(self.auth_failed_timeout, callback, self.username, password, msg)
        self.username = ""

    async def handle_auth_success(self, home, password, msg_login):
        if len(msg_login) < 75:
            await self.respond("230 %s" % msg_login)
        else:
            await self.push("230-%s\r\n" % msg_login)
            await self.respond("230 ")
        self.log("USER '%s' logged in." % self.username)
        self.authenticated = True
        self.password = password
        self.attempted_login_times = 0
        self.fs = self.abstracted_fs(home, self)
        self.on_login(self.username)

    def on_login(self, username):
        pass

    def on_login_failed(self, username: str, password: str) -> None:
        pass

    def on_logout(self, username):
        pass

    async def ftp_ACCT(self, line):
        pass


def find_prefix_at_end(haystack, needle):
    length = len(needle) - 1
    while length and not haystack.endswith(needle[:length]):
        length -= 1
    return length
