import os, select
from errno import *
import security

import logging

vfslog    = logging.getLogger("sandbox.vfs")
bridgelog = logging.getLogger("sandbox.bridge")

class VfsManager(object):
    def __init__(self, lowest_fd, highest_fd, root='/tmp'):
        self.root=root
        self.bridge = DescriptorBridger(lowest_fd, highest_fd)
        self.security = security.SecurityManager()

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
        self.security.open(filename, perms, mode)
        untrustedfd = self.do_open(path, perms, mode)
        self.security.register_descriptor(untrustedfd[0], filename)
        return untrustedfd

    def do_open(self, filename, perms, mode):
        try:
            local = os.open(filename, perms)
        except OSError, e:
            return (-1, e.errno)
        remote = self.bridge.link(local)
        return (remote, 0)

    def fstat(self, remote):
        if not self.security.fstat(remote):
            return (-1, None, EPERM)
        try:
            local = self.bridge.get(remote)
        except KeyError:
            vfslog.error('%d: no such file descriptor' % remote)
            return (0xffffffff, None, EBADF)
        try:
            st = os.fstat(local)
            ret = 0
            errno = 0
        except Exception, e:
            vfslog.error('os.fstat(%d) failed: %s' % (local, e.errno[1]))
            st  = None
            ret = 0xffffffff
            errno = e.errno
        return (ret, st, errno)

    def close(self, fd):
        ret = (-1, 0)
        if self.security.unregister_descriptor(fd):
            pass
        return ret

    def is_at_eof(self, remote):
        local = self.bridge.get(remote)
        ret = local in self.bridge.at_eof
        if not ret:
            vfslog.debug('File descriptor %d/%d is at EOF' % (remote, local))
        return ret

    def read_handler(self, remote, buflen):
        local = self.bridge.get(remote)
        return os.read(local, buflen)

class DescriptorBridger:
    def __init__(self, minimum, maximum):
        self.descriptors = {}
        self.at_eof      = []
        self.min    = minimum
        self.max    = maximum

    def link(self, local):
        remote = 0
        i=self.min
        while not remote and i <= self.max:
            if not i in self.descriptors:
                remote = i
                self.register(local, remote)
            i += 1
        return remote

    def register(self, local, remote):
        bridgelog.debug('register(%d, %d)' % (local, remote))
        self.descriptors[local] = remote
        self.descriptors[remote] = local

    def unregister(self, local):
        bridgelog.debug('unregistering(%d)' % local)
        remote = self.descriptors[local]
        bridgelog.debug(' %d,%d removed' % (local, remote))
        del(self.descriptors[remote])
        del(self.descriptors[local])

    def get(self, i):
        return self.descriptors[i]

    def run(self, control):
        while True:
            watch = [control]
            (rlist, wlist, xlist) = select.select(watch, [], [], 30)
            if not rlist:
                continue

            if control in rlist:
                return True
        return False

if __name__ == "__main__":
    import doctest
    doctest.testmod()
