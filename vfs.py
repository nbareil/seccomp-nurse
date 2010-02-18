import os, select
from errno import *
# from ctypes import *

# class Stat(ctypes.Structure):
#     _fields_ = [ ('st_dev', c_ulonglong),
#                  ('st_ino', c_ulong),
#                  ('st_mode', c_uint),
#                  ('st_nlink', c_uint),
#                  ('st_uid', c_uint),
#                  ('st_gid', c_uint),
#                  ('st_rdev', c_ulonglong),
#                  ('st_size', c_long),
#                  ('st_blksize', c_long),
#                  ('st_blocks', c_long),
#                  ('st_atime', c_long),
#                  ('st_mtime', c_long),
#                  ('st_ctime', c_long) ]

class VfsManager(object):
    def __init__(self, nextfd=-1, root='/tmp'):
        self.root=root
        self.nextfd = nextfd
        self.fd_bridges = []

    def check_acl(self, path, mode):
        return path.startswith(self.root)

    def access(self, filename, mode):
        """

        >>> import os
        >>> v=VfsManager(root='/etc')
        >>> v.access('/home/', os.R_OK)
        False
        >>> v.access('/tata', os.R_OK)
        False
        >>> v.access('/etc/passwd', os.R_OK)
        True
        """
        path = os.path.realpath(filename)
        if not os.access(path, mode):
            return False
        return self.check_acl(path, mode)

    def open(self, filename, perms, mode):
        path = os.path.realpath(filename)
        if not self.check_acl(path, perms):
            return (-1, EPERM)
        ### XXX cas ou il faille creer le fichier
        return self.open_dup(path, perms, mode)

    def open_dup(self, filename, perms, mode):
        try:
            fd = os.open(filename, perms)
        except IOError, e:
            return (-1, e.errno)
        dupfd = self.nextfd
        self.fd_bridges.append((fd, dupfd))
        self.nextfd += 1 ####  XXX: We need to verify +1
        return (dupfd+1, 0) #### +1 because the untrusted has an offset of -1

    def select_loop(self, controlfd):
        while True:
            fd_flat=[]
            for fdtuple in self.fd_bridges:
                fd_flat += list(fdtuple)
            rfd_flat = fd_flat + [controlfd]
            (rlist, wlist, xlist) = select.select(rfd_flat, fd_flat, [], 30)
            if rlist:
                # print rlist
                if controlfd in rlist:
                    return True
                else:
                    for a,b in self.fd_bridges:
                        if a in rlist and b in wlist:
                            buf = os.read(a, 512)
                            if not buf:
                                ### XXX: remove the file descriptor
                                self.fd_bridges=[]
                                os.close(a)
                                os.close(b)
                            else:
                                os.write(b, buf)
                        if b in rlist and a in wlist:
                            os.write(a, os.read(b, 512))
        return False

    def fstat(self, fd):
        try:
            st = os.fstat(fd)
            ret = 0
            errno = 0
        except Exception, e:
            st  = None
            ret = -1
            errno = e.errno
        return (ret, st, errno)

    def close(self, fd):
        return (0, 0,)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
