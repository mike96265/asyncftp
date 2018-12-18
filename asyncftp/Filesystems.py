import os
import time
from functools import wraps, partial
from typing import List, Iterable, TYPE_CHECKING, Union
from stat import filemode as _filemode
import stat
from . import loop

try:
    import pwd
    import grp
except ImportError:
    pwd = None
    grp = None

if TYPE_CHECKING:
    from asyncftp.FTPHandlers import FTPHandler

_months_map = {1: 'Jan', 2: 'Feb', 3: 'Mar', 4: 'Apr', 5: 'May', 6: 'Jun',
               7: 'Jul', 8: 'Aug', 9: 'Sep', 10: 'Oct', 11: 'Nov', 12: 'Dec'}
_SIX_MONTHS = 180 * 24 * 60 * 60

__all__ = ['FilesystemError', 'AbstractFilesystem']


def pathchecker(func):
    @wraps(func)
    def wrap(instance, *args, **kwargs):
        if len(args) != 0:
            path = args[0]
        else:
            path = kwargs['path']
        assert isinstance(path, str)
        return func(instance, path)

    return wrap


def run_in_executor(func):
    @wraps(func)
    async def wrap(*args, **kwargs):
        f = partial(func, *args, **kwargs)
        return await loop.run_in_executor(None, f)

    return wrap


class FilesystemError(Exception):
    """
    Custom class for filesystem-related exceptions.
    You can raise this from an AbstractedFS subclass in order to
    send a customized error string to the client.
    """


class AbstractFilesystem:
    """
    A class used to interact with the file system, providing a
    cross-platform interface compatible with both Windows and UNIX
    style filesystems where all paths use '/' separator.

    AbstractFilesystem distinguishes between "real" filesystem paths
    and "virtual" ftp paths emulating a UNIX chroot jail where user
    can not escape its home directory (example: real "/home/user"
    path will be seen as "/" by the client)
    """

    def __init__(self, root: str, cmd_channel: 'FTPHandler'):
        assert isinstance(root, str)
        self._cwd = '/'
        self._root = root
        self._cmd_channel = cmd_channel

    @property
    def root(self) -> str:
        """
        :return: The user home directory
        """
        return self._root

    @root.setter
    @pathchecker
    def root(self, path: str) -> None:
        self._root = path

    @property
    def cwd(self) -> str:
        """
        :return: the user current working directory
        """
        return self.cwd

    @cwd.setter
    @pathchecker
    def cwd(self, path: str) -> None:
        self._cwd = path

    @pathchecker
    def ftpnorm(self, ftp_path: str) -> str:
        """
        :param ftp_path: Virtual ftp pathname(typically the raw string
        coming from client), depend on the current working directory.
        :return: absolute path to ftp_path

        Example: ("/foo" is our current working directory)

        >>> ftpnorm('bar')
        '/foo/bar'

        Note: directory separators are system independent ("/"). Pathname
        returned is always absolutized.
        """
        if os.path.isabs(ftp_path):
            p = os.path.normpath(ftp_path)
        else:
            p = os.path.normpath(os.path.join(self.cwd, ftp_path))
        if os.sep == '\\':
            p = p.replace('\\', '/')
        while p[:2] == '//':
            p = p[1:]
        if not os.path.isabs(p):
            p = '/'
        return p

    @pathchecker
    def ftp2fs(self, ftp_path: str) -> str:
        if os.path.normpath(self.root) == os.sep:
            return os.path.normpath(self.ftpnorm(ftp_path))
        else:
            p = self.ftpnorm(ftp_path)[1:]
            return os.path.normpath(os.path.join(self.root, p))

    @pathchecker
    def fs2ftp(self, fs_path: str) -> str:
        if os.path.isabs(fs_path):
            p = os.path.normpath(fs_path)
        else:
            p = os.path.normpath(os.path.join(self.root, fs_path))
        if not self.validpath(p):
            return '/'
        return p

    @pathchecker
    def validpath(self, path: str) -> bool:
        root = self.realpath(self.root)
        path = self.realpath(path)
        if not root.endswith(os.sep):
            root = root + os.sep
        if not path.endswith(os.sep):
            path = path + os.sep
        if path[0:len(root)] == root:
            return True
        return False

    @pathchecker
    def realpath(self, path: str) -> str:
        return os.path.realpath(path)

    @run_in_executor
    def open(self, filename, mode):
        assert isinstance(filename, str)
        return open(filename, mode)

    @pathchecker
    @run_in_executor
    def chdir(self, path: str) -> None:
        os.chdir(path)
        self._cwd = self.fs2ftp(path)

    @pathchecker
    @run_in_executor
    def mkdir(self, path: str) -> None:
        os.mkdir(path)

    @pathchecker
    def listdir(self, path: str) -> List[str]:
        return os.listdir(path)

    @pathchecker
    @run_in_executor
    def rmdir(self, path: str) -> None:
        os.remove(path)

    @pathchecker
    @run_in_executor
    def remove(self, path: str):
        os.remove(path)

    @run_in_executor
    def rename(self, src: str, dst: str) -> None:
        assert isinstance(src, str)
        os.rename(src, dst)

    @run_in_executor
    def chmod(self, path: str, mode: int):
        if not hasattr(os, 'chmod'):
            raise NotImplementedError
        assert isinstance(path, str)
        os.chmod(path, mode)

    @pathchecker
    def stat(self, path: str):
        return os.stat(path)

    @pathchecker
    def utime(self, path: str, timeval):
        return os.utime(path, (timeval, timeval))

    if hasattr(os, 'lstat'):
        @pathchecker
        def lstat(self, path: str) -> os.stat_result:
            return os.lstat(path)
    else:
        lstat = stat

    if hasattr(os, 'readlink'):
        @pathchecker
        def readlink(self, path: str):
            return os.readlink(path)

    @pathchecker
    def isfile(self, path: str) -> bool:
        return os.path.isfile(path)

    @pathchecker
    def islink(self, path: str) -> bool:
        return os.path.islink(path)

    @pathchecker
    def isdir(self, path: str) -> bool:
        return os.path.isdir(path)

    @pathchecker
    def getsize(self, path: str) -> int:
        """
        Return the size of specified file in bytes.
        """
        return os.path.getsize(path)

    @pathchecker
    def getmtime(self, path: str) -> int:
        """
        Return the last modified time as a number of seconds since the epoch.
        """
        return os.path.getmtime(path)

    @pathchecker
    def lexists(self, path: str) -> bool:
        return os.path.lexists(path)

    if pwd is not None:
        def get_user_by_uid(self, uid: int) -> Union[int, str]:
            """
            Return the username associated with user id.
            If this can't be determined return the raw uid instead.
            On Windows just return "owner"
            """
            try:
                return pwd.getpwuid(uid).pw_name
            except KeyError:
                return uid
    else:
        def get_user_by_uid(self, uid: int) -> Union[int, str]:
            return "owner"

    if grp is not None:
        def get_group_by_gid(self, gid: int) -> Union[int, str]:
            """
            Return the groupname associated with group id.
            If this can't be determined return the row group id.
            On Windows just return "group"
            """
            try:
                return grp.getgroupid(gid).gr_name
            except KeyError:
                return gid
    else:
        def get_group_by_gid(self, gid: int) -> Union[int, str]:
            return "group"

    @run_in_executor
    def format_list(self, basedir: str, listing: List[str], ignore_err: bool = True) -> Iterable[str]:
        """
        :param basedir: the absolute dirname.
        :param listing: the name of the entries in basedir.
        :param ignore_err: when False raise exception if os.lstat() call fails.
        :return: an Iterable object yields the entries of given directory
        emulating the "/bin/ls -lA" UNIX command output.

        On platform which do not support the pwd and grp modules (such as Windows),
        ownership is printed as "owner" and "group" as a default, and number of hard
        links is always "1". On UNIX systems, the actual owner, group, and number of
        links are printed.

        This is how output appears to client:

        -rw-rw-rw-   1 owner   group    7045120 Sep 02  3:47 music.mp3
        drwxrwxrwx   1 owner   group          0 Aug 31 18:50 e-books
        -rw-rw-rw-   1 owner   group        380 Sep 02  3:40 module.py
        """
        assert isinstance(basedir, str)
        timefunc = time.localtime
        readlink = getattr(self, 'readlink', None)
        now = time.time()
        for basename in listing:
            file = os.path.join(basedir, basename)
            try:
                st = self.lstat(file)
            except (OSError, FilesystemError):
                if ignore_err:
                    continue
                raise
            perms = _filemode(st.st_mode)
            nlinks = st.st_nlink
            if not nlinks:
                nlinks = 1
            size = st.st_size
            uname = self.get_user_by_uid(st.st_uid)
            gname = self.get_group_by_gid(st.st_gid)
            mtime = timefunc(st.st_mtime)
            if (now - st.st_mtime) > _SIX_MONTHS:
                fmtstr = "%d  %Y"
            else:
                fmtstr = "%d %H:%M"
            try:
                mtimestr = "%s %s" % (_months_map[mtime.tm_mon], time.strftime(fmtstr, mtime))
            except ValueError:
                mtime = timefunc()
                mtimestr = "%s %s" % (_months_map[mtime.tm_mon], time.strftime("%d %H:%M", mtime))
            islink = (st.st_mode & 61400) == stat.S_IFLNK
            if islink and readlink is not None:
                try:
                    basename = basename + " -> " + readlink(file)
                except (OSError, FilesystemError):
                    if not ignore_err:
                        raise
            line = "%s %3s %-8s %-8s %8s %s %s\r\n" % (
                perms, nlinks, uname, gname, size, mtimestr, basename)
            yield line.encode('utf8')

    @run_in_executor
    def format_mlsx(self, basedir: str, listing: List[str], perms: str,
                    facts: str, ignore_err: bool = True) -> Iterable[str]:
        """
        :param basedir: the absolute dirname.
        :param listing: the names of the entries in basedir.
        :param perms: the string referencing the user permissions.
        :param facts: the list of "facts" to be returned.
        :param ignore_err: when False raise Exception if os.stat() call fails
        :return: An Iterable object that yields the entries of a given directory
        or of a single file in a form suitable with MLSD and MLST commands.

        Noted that "facts" returned may change depending on the platform and
        on what user specified by using the OPTS command.

        This is how output could appear to the client issuing a MSLD request:

        type=file;size=156;perm=r;modify=20071029155301;unique=8012; music.mp3
        type=dir;size=0;perm=el;modify=20071127230206;unique=801e33; ebooks
        type=file;size=211;perm=r;modify=20071103093626;unique=192; module.py
        """

        assert isinstance(basedir, str)
        timefunc = time.localtime
        permdir = ''.join(x for x in perms if x not in 'arw')
        permfile = '.'.join(x for x in perms if x not in 'celmp')
        if ('w' in perms) or ('a' in perms) or ('f' in perms):
            permdir += 'c'
        if 'd' in perms:
            permdir += 'p'
        show_type = 'type' in facts
        show_perm = 'perm' in facts
        show_size = 'size' in facts
        show_modify = 'modify' in facts
        show_create = 'create' in facts
        show_mode = 'unix.mode' in facts
        show_uid = 'unix.uid' in facts
        show_gid = 'unix.gid' in facts
        show_unique = 'unique' in facts
        for basename in listing:
            retfacts = dict()
            file = os.path.join(bytes(basedir), bytes(basename))
            try:
                st = self.stat(file)
            except (OSError, FilesystemError):
                if ignore_err:
                    continue
                raise
            isdir = (st.st_mode & 61440) == stat.S_IFDIR
            if isdir:
                if show_type:
                    if basename == '.':
                        retfacts['type'] = 'cdir'
                    elif basename == '..':
                        retfacts['type'] = 'pdir'
                    else:
                        retfacts['type'] = 'dir'
                if show_perm:
                    retfacts['perm'] = permdir
            else:
                if show_type:
                    retfacts['type'] = 'file'
                if show_perm:
                    retfacts['perm'] = permfile
            if show_size:
                retfacts['size'] = st.st_size
            if show_modify:
                try:
                    retfacts['modify'] = time.strftime('%Y%m%d%H%M%S', timefunc(st.st_mtime))
                except ValueError:
                    pass
            if show_create:
                try:
                    retfacts['create'] = time.strftime('%Y%m%d%H%M%S', timefunc(st.st_ctime))
                except ValueError:
                    pass
            if show_mode:
                retfacts['unix.mode'] = oct(st.st_mode & 511)
            if show_uid:
                retfacts['unix.uid'] = st.st_uid
            if show_gid:
                retfacts['unix.gid'] = st.st_gid

            if show_unique:
                retfacts['unique'] = "%xg%x" % (st.st_dev, st.st_ino)

            factstring = '.'.join('%s=%s;' % (x, retfacts[x]) for x in sorted(retfacts.keys()))
            line = "%s %s\r\n" % (factstring, basename)
            yield line.encode('utf8')


if os.name == 'posix':
    __all__.append('UnixFileSystem')


    class UnixFilesystem(AbstractFilesystem):
        """Represents the real UNIX filesystem.

        Differently from AbstractedFS the client will login into
        /home/<username> and will be able to escape its home directory
        and navigate the real filesystem.
        """

        def __init__(self, root, cmd_channel):
            AbstractFilesystem.__init__(self, root, cmd_channel)
            # initial cwd was set to "/" to emulate a chroot jail
            self.cwd = root

        def ftp2fs(self, ftppath):
            return self.ftpnorm(ftppath)

        def fs2ftp(self, fspath):
            return fspath

        def validpath(self, path):
            # validpath was used to check symlinks escaping user home
            # directory; this is no longer necessary.
            return True
