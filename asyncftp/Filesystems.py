import asyncio
import functools
from concurrent.futures import ProcessPoolExecutor
import os
from stat import filemode as _filemode
import stat
import time
from typing import List, Iterable, TYPE_CHECKING, Union

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


class AbstractAsyncLister:

    def __init__(self, loop=None):
        self.loop = loop or asyncio.get_event_loop()

    def __aiter__(self):
        return self

    async def __anext__(self):
        raise NotImplementedError


class AsyncFileContext:

    def __init__(self, filesystem: 'AbstractFilesystem', args, kwargs):
        self.close = None
        self.filesystem = filesystem
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self):
        self.file = await self.filesystem._open(*self.args, **self.kwargs)
        self.seek = functools.partial(self.filesystem.seek, self.file)
        self.write = functools.partial(self.filesystem.write, self.file)
        self.read = functools.partial(self.filesystem.read, self.file)
        self.close = functools.partial(self.filesystem.close, self.file)
        return self

    async def __aexit__(self, *args):
        if self.close is not None:
            await self.close()

    def __await__(self):
        return self.__aenter__().__await__()


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

    def __init__(self, root: str, handler: 'FTPHandler'):
        if not os.path.isabs(root):
            raise FilesystemError("the root directory should always be absolute")
        self._root = root
        self.handler = handler
        self._cwd = '/'

    @property
    def root(self) -> str:
        return self._root

    @root.setter
    def root(self, path: str):
        self._root = path

    @property
    def cwd(self) -> str:
        return self.cwd

    @cwd.setter
    def cwd(self, path: str):
        self._cwd = path

    def chdir(self, path: str):
        self.cwd = path

    # method bellow manage path between ftp handler and filesystem,
    # and usually has no need to deal with I/O
    # 1. ftpnorm
    # 2. ftp2fs
    # 3. fs2ftp
    # 4. realpath

    def ftpnorm(self, ftp_path: str) -> str:
        """
        Normalize a "virtual" ftp pathname (typically the raw string
        coming from client) depending on the current working directory.

        Example (having "/foo" as current working directory):
        >>> self.ftpnorm('bar')
        '/foo/bar'

        Note: directory separators are system independent ("/").
        Pathname returned is always absolutized.
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

    def ftp2fs(self, ftp_path: str) -> str:
        """
        Translate a virtual ftp pathname (typically the raw string coming from client)
        into equivalent absolute real filesystem pathname.

        Example (having "/home/user" as root directory and /foo as cwd)

        >>> self.ftp2fs("bar")
        '/home/user/foo/bar'
        """
        if os.path.normpath(self.root) == os.sep:
            return os.path.normpath(self.ftpnorm(ftp_path))
        else:
            p = self.ftpnorm(ftp_path)[1:]
            return os.path.normpath(os.path.join(self.root, p))

    def fs2ftp(self, fs_path: str) -> str:
        """
        Translate a "real" filesystem pathname into equivalent absolute "virtual" ftp
        pathname depending on the user's root directory.

        Example (having "/home/user" as root directory):

        >>> self.fs2ftp('/home/user/foo')
        'foo'

        As for ftpnorm, directory separators are system independent ("/") and pathname
        returned is always absolute.

        Pathname escaping from user's root directory (e.g. "/home" when
        root is "/home/user") always return "/".
        """
        if os.path.isabs(fs_path):
            p = os.path.normpath(fs_path)
        else:
            p = os.path.normpath(os.path.join(self.root, fs_path))
        if not self.validpath(p):
            return '/'
        return p

    def validpath(self, path: str) -> bool:
        """
        Check if the path belongs to user's home directory.
        Expected argument is a "real" filesystem pathname.

        If path is a symbolic link it is resolved to check its origin file.

        Pathname escaping from user's root directory are considered not valid
        """
        root = self.realpath(self.root)
        path = self.realpath(path)
        if not root.endswith(os.sep):
            root = root + os.sep
        if not path.endswith(os.sep):
            path = path + os.sep
        if path[0:len(root)] == root:
            return True
        return False

    realpath = os.path.realpath

    # method bellow is related to file management
    # 1. isfile (public)
    # 2. open (public)
    # 3. remove (public)
    # 4. islink (private)
    # 5. readlink

    async def isfile(self, path: str) -> bool:
        raise NotImplementedError

    async def _open(self, path: str, mode: str):
        raise NotImplementedError

    def open(self, *args, **kwargs):
        return AsyncFileContext(self, args, kwargs)

    async def remove(self, path: str):
        raise NotImplementedError

    async def islink(self, path: str) -> bool:
        raise NotImplementedError

    async def readlink(self, path: str):
        raise NotImplementedError

    async def seek(self, file, *args, **kwargs):
        raise NotImplementedError

    async def write(self, file, *args, **kwargs):
        raise NotImplementedError

    async def read(self, file, *args, **kwargs):
        raise NotImplementedError

    async def close(self, file):
        raise NotImplementedError

    # method bellow is related to directory management
    # 1. isdir (public)
    # 2. mkdir (public)
    # 3. rmdir (public)
    # 4. listdir (public)

    async def isdir(self, path: str) -> bool:
        raise NotImplementedError

    async def mkdir(self, path: str):
        raise NotImplementedError

    async def rmdir(self, path: str):
        raise NotImplementedError

    async def listdir(self, path: str) -> List[str]:
        raise NotImplementedError

    # method bellow is related to file and directory management
    # 1. chdir (public)
    # 2. rename (public)
    # 3. utime (public)
    # 4. stat (private)
    # 5. lstat (public)
    # 6. getsize (public)
    # 7. getmtime (public)
    # 8. lexists (public)
    # 9. get_user_by_uid (private)
    # 10. get_group_by_gid (private)

    async def chmod(self, path: str, mode: int):
        raise NotImplementedError

    async def rename(self, src: str, dst: str):
        raise NotImplementedError

    async def utime(self, path: str, timeval: int):
        """
        Perform a utime() system call on given path.
        utime() system call is to change file's last access time and modify time (atime, mtime)
        """
        raise NotImplementedError

    async def stat(self, path: str) -> os.stat_result:
        """
        Perform a stat() system call on given path.

        Example:
        >>> os.stat('/home/user/abc')
        os.stat_result(st_mode=16877, st_ino=2533274790468575, st_dev=2, st_nlink=1, st_uid=1000,
        st_gid=1000, st_size=4096, st_atime=1545288484, st_mtime=1545376980, st_ctime=1545401153)
        """
        raise NotImplementedError

    async def lstat(self, path: str) -> os.stat_result:
        """Like stat but does not follow symbolic links"""
        raise NotImplementedError

    async def getsize(self, path: str) -> int:
        """Return the size of specified file in bytes."""
        raise NotImplementedError

    async def getmtime(self, path: str) -> int:
        """Return the last modified time as a number of seconds since the epoch."""
        raise NotImplementedError

    async def lexists(self, path: str) -> bool:
        raise NotImplementedError

    def get_user_by_uid(self, uid: int) -> Union[int, str]:
        """
        Return the username associated with user id.
        If this can't be determined return the raw uid instead.
        On Windows just return "owner"
        """
        if pwd is not None:
            try:
                return pwd.getpwuid(uid).pw_name
            except KeyError:
                return uid
        else:
            return "owner"

    def get_group_by_gid(self, gid: int) -> Union[int, str]:
        """
        Return the groupname associated with group id.
        If this can't be determined return the row group id.
        On Windows just return "group"
        """
        if grp is not None:
            try:
                return grp.getgroupid(gid).gr_name
            except KeyError:
                return gid
        else:
            return "group"

    # bellow method is direct related to ftp command list and mlsx

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
        raise NotImplementedError

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
                st = os.stat(file)
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


class BlockingFilesystem(AbstractFilesystem):

    # method bellow is related to file management
    # 1. isfile (public)
    # 2. open (public)
    # 3. remove (public)
    # 4. islink (private)
    # 5. readlink

    async def isfile(self, path: str) -> bool:
        return os.path.isfile(path)

    async def _open(self, path: str, *args, **kwargs):
        return open(path, *args, **kwargs)

    async def remove(self, path: str):
        return os.remove(path)

    async def islink(self, path: str) -> bool:
        return os.path.islink(path)

    async def readlink(self, path):
        return os.readlink(path)

    async def seek(self, file, *args, **kwargs):
        return file.seek(*args, **kwargs)

    async def write(self, file, *args, **kwargs):
        return file.write(*args, **kwargs)

    async def read(self, file, *args, **kwargs):
        return file.read(*args, **kwargs)

    async def close(self, file):
        return file.close()

    # method bellow is related to directory management
    # 1. isdir (public)
    # 2. mkdir (public)
    # 3. rmdir (public)
    # 4. listdir (public)

    async def isdir(self, path: str) -> bool:
        return os.path.isdir(path)

    async def mkdir(self, path: str):
        return os.mkdir(path)

    async def rmdir(self, path: str):
        return os.rmdir(path)

    async def listdir(self, path: str) -> List[str]:
        return os.listdir(path)

    # method bellow is related to file and directory management
    # 1. chdir (public)
    # 2. rename (public)
    # 3. utime (public)
    # 4. stat (private)
    # 5. lstat (public)
    # 6. getsize (public)
    # 7. getmtime (public)
    # 8. lexists (public)
    # 9. get_user_by_uid (private)
    # 10. get_group_by_gid (private)

    async def chmod(self, path: str, mode: int):
        return os.chmod(path, mode)

    async def rename(self, src: str, dst: str):
        return os.rename(src, dst)

    async def utime(self, path: str, timeval: int):
        """
        Perform a utime() system call on given path.
        utime() system call is to change file's last access time and modify time (atime, mtime)
        """
        return os.utime(path, (timeval, timeval))

    async def stat(self, path: str) -> os.stat_result:
        """
        Perform a stat() system call on given path.

        Example:
        >>> os.stat('/home/user/abc')
        os.stat_result(st_mode=16877, st_ino=2533274790468575, st_dev=2, st_nlink=1, st_uid=1000,
        st_gid=1000, st_size=4096, st_atime=1545288484, st_mtime=1545376980, st_ctime=1545401153)
        """
        return os.stat(path)

    async def lstat(self, path: str) -> os.stat_result:
        """Like stat but does not follow symbolic links"""
        return os.lstat(path)

    async def getsize(self, path: str) -> int:
        """Return the size of specified file in bytes."""
        return os.path.getsize(path)

    async def getmtime(self, path: str) -> int:
        """Return the last modified time as a number of seconds since the epoch."""
        return os.path.getmtime(path)

    async def lexists(self, path: str) -> bool:
        return os.path.lexists(path)

    def format_list(self, basedir: str, listing: List[str], ignore_err: bool = True):
        class Lister(AbstractAsyncLister):
            iter = None

            async def __anext__(lister):
                if lister.iter is None:
                    lister.iter = self._format_list(basedir, listing, ignore_err)
                try:
                    return next(lister.iter)
                except StopIteration:
                    raise StopAsyncIteration

        return Lister(loop=self.handler.loop)

    def _format_list(self, basedir: str, listing: List[str], ignore_err: bool = True):
        if self.handler.use_gmt_times:
            timefunc = time.gmtime
        else:
            timefunc = time.localtime
        SIX_MONTH = 180 * 24 * 60 * 60
        readlink = getattr(self, 'readlink', None)
        now = time.time()
        for filename in listing:
            file = os.path.join(basedir, filename)
            try:
                st = os.lstat(file)
            except (OSError, FilesystemError) as err:
                if ignore_err:
                    continue
                raise err
            perms = _filemode(st.st_mode)
            nlinks = st.st_nlink
            if not nlinks:
                nlinks = 1
            size = st.st_size
            uname = self.get_user_by_uid(st.st_uid)
            gname = self.get_group_by_gid(st.st_gid)
            mtime = timefunc(st.st_mtime)
            if (now - st.st_mtime) > SIX_MONTH:
                fmtstr = "%d %Y"
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
                    filename = filename + " -> " + readlink(file)
                except (OSError, FilesystemError) as err:
                    if not ignore_err:
                        raise err
            line = "%s %3s %-8s %-8s %8s %s %s\r\n" % (
                perms, nlinks, uname, gname, size, mtimestr, filename)
            yield line


if os.name == 'posix':
    __all__.append('UnixFileSystem')


    class UnixFilesystem(AbstractFilesystem):
        """Represents the real UNIX filesystem.

        Differently from AbstractedFS the client will login into
        /home/<username> and will be able to escape its home directory
        and navigate the real filesystem.
        """

        def __init__(self, root, handler):
            AbstractFilesystem.__init__(self, root, handler)
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
