#! /usr/bin/env python

import os, struct

REGISTERS_DROPBOX_LEN = 7*4

class TrustedThread(object):
    def __init__(self, fd, mapping):
        self.mapping = mapping
        self.freespace_start = REGISTERS_DROPBOX_LEN
        self.thread  = os.fdopen(fd, 'w+')
        self.r_baseaddr = struct.unpack('I', self.thread.read(4))[0]

    def delegate(self, mm):
        for name in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']:
            value = getattr(mm, name)
            if isinstance(value, str):
                ptr = self.push_volatile(value)
                setattr(mm, name, ptr)
        self.push_registers(mm)
        self.wakeup()
        ret = struct.unpack('I', self.thread.read(4))[0]
        self.forget()
        return ret

    def push_registers(self, mm):
        raw = mm.pack()
        self.mapping[:len(raw)] = raw

    def wakeup(self):
        self.thread.write('PING')
        self.thread.flush()

    def push_volatile(self, value):
        start = self.freespace_start
        end   = start + len(value)
        if end-start > self.mapping.size():
            raise Exception('Not enought memory to store value argument')
        self.mapping[start:end] = value
        self.freespace_start = end
        return start+self.r_baseaddr

    def forget(self):
        """
        syscall has been performed, we can now "free" the memory.

        """
        self.freespace_start = REGISTERS_DROPBOX_LEN
        self.mapping[:] = '\x00'*self.mapping.size()
