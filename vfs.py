import os, select
from errno import *

class VfsManager(object):
    def __init__(self, nextfd=-1, root='/tmp'):
        self.root=root
        self.nextfd = nextfd
        self.fd_bridges = []

    def check_acl(self, path, mode):
        print 'path=%s\nroot=%s\n' % (path, self.root)
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
            fd = os.open(filename, perms, mode)
        except IOError, e:
            return (-1, e.errno)
        dupfd = self.nextfd
        self.fd_bridges.append((fd, dupfd))
        self.nextfd += 1
        return (dupfd, 0)

    def select_loop(self, controlfd):
        while True:
            fd_flat=[]
            for fdtuple in self.fd_bridges:
                fd_flat += list(fdtuple)
            fd_flat += [controlfd]
            (rlist, wlist, xlist) = select.select(fd_flat, [], [])
            if rlist:
                if controlfd in rlist:
                    return True
                else:
                    for a,b in self.fd_bridges:
                        if a in rlist:
                            buf = os.read(a, 512)
                            print ' %d ~~> %d  "%s"' % (a, b, buf)
                            os.write(b, buf)
                        if b in rlist:
                            os.write(a, os.read(b, 512))
        return False

if __name__ == "__main__":
    import doctest
    doctest.testmod()
