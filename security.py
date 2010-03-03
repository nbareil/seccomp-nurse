#! /usr/bin/env python

import logging, os
securitylog = logging.getLogger("sandbox.security")

class SecurityManager(object):
    def __init__(self, fs_root='/'):
        self.fs_root  = fs_root
        self.fd_table = {}

    def register_descriptor(self, fd, filename):
        if fd in self.fd_table:
            raise SecurityException('File descriptor %d already opened!' % fd)
        self.fd_table[fd] = filename
        securitylog.debug('Registering file descriptor %d associated to %s' % (fd, filename))


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
        ret = (0 <= fd <= 2) or (fd in self.fd_table)
        securitylog.info('Can fstat(%d)? %s' % (fd, ret))
        return ret

    
