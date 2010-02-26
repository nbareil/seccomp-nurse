#! /usr/bin/env python

import logging
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(name)15.15s %(levelname)5s: %(message)s"))
securitylog = logging.getLogger("sandbox.vfs")
securitylog.addHandler(console_handler)
securitylog.setLevel(-1)

class Security(object):
    def __init__(self, fs_root='/'):
        self.fs_root  = fs_root
        self.fd_table = []

    def register_descriptor(self, fd, filename):
        if fd in self.fd_table:
            raise SecurityException('File descriptor %d already opened!' % fd)
        securitylog.debug('Registering file descriptor %d associated to %s' % self.fd_table[fd])
        self.fd_table[fd] = filename

    # Trying to close a not-opened-file-descriptor is not
    # fatal because daemons usually try to close every
    # file descriptors at init.
    def unregister_descriptor(self, fd):
        opened = fd in self.fd_table
        if opened:
            del(self.fd_table[fd])
        return opened

    def open(self, filename, perms, mode):
        pass

    def fstat(self, fd):
        ret = fd in self.fd_table
        securitylog.info('Can fstat(%d)? %s' % ret)
        return ret

    
