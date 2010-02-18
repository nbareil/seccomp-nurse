#! /usr/bin/env python

class VirtualMemory:
    def __init__(self, size):
        self.pool = None

    def new_mapping(self, addr, length, prot, flags):
        return self.pool

    def release_mapping(self, addr, length):
        pass

    def set_pool_addr(self, addr):
        self.pool = addr
