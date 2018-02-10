#!/usr/bin/env python
# -*- encoding:utf-8 -*-
import os
import subprocess
import sys

ALGORITHM = 'default'
IN_PLACE = False

def execute_cmd(cmd, printInfo=True):
    if not printInfo:
        exe_cmd = cmd + " > /dev/null"
    else:
        exe_cmd = cmd

    result = os.system(exe_cmd)
    if (result != 0):
        print "[ERROR] CMD: " + cmd
    else:
        print "[SUCCESS] CMD: " + cmd
    return result

def RunCommand(cmd, cwd=None):
  process = subprocess.Popen(cmd, cwd=cwd)
  process.wait()
  return process.returncode

def compress_alg_lzma(src, dest):
    current = os.getcwd()
    cmd = ['7z', 'a', dest, src]
    print '[INFO]', ' '.join(cmd)
    if RunCommand(cmd) != 0:
        print '[ERROR] 7z failed!', ' '.join(cmd)
        return ''

    return meta

def print_help():
    print '''compress.py [options]
    Options:
        --alg       algorithms
        --inmem     in memory 
        --src       src library
        --dst       dest file
    '''

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print_help()
        exit(0)

    args = sys.argv[1:]
    print args, len(args)
    SRC = ''
    DEST = ''
    for i in range(len(args) - 2, -1, -1):
        if args[i] == '--alg':
            ALGORITHM = args[i + 1]
            del args[i + 1], args[i]
        elif args[i] == '--inmem':
            IN_PLACE = True
            del args[i]
        elif args[i] == '--src':
            SRC = args[i + 1]
            del args[i + 1], args[i]
        elif args[i] == '--dst':
            DEST = args[i + 1]
            del args[i + 1], args[i]

    print ALGORITHM, IN_PLACE, SRC, DEST
    compress_alg_lzma(SRC, DEST)
