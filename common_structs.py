"""
 Filename: common_structs.py
 Description: Just a place to store structs used by various Windows API calls.
 Created by: Benjamin M. Singleton
 Created: 03-10-2020
"""

import ctypes
from ctypes.wintypes import HANDLE, DWORD


# the name of the class doesn't have to match the real struct's name, but it
# has does have to inherit ctypes.Structure
class PROCESS_INFORMATION(ctypes.Structure):
    # ctypes looks for _fields_ in a struct, and it expects it to be a list of tuples
    _fields_ = [
        # each tuple is a pair of value name and type, in that order
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD)
    ]


class STARTUPINFOA(ctypes.Structure):
    _fields_ = [
        ('cb', 'DWORD'),
        ('lpReserved', 'LPSTR'),
        ('lpDesktop', 'LPSTR'),
        ('lpTitle', 'LPSTR'),
        ('dwX', 'DWORD'),
        ('dwY', 'DWORD'),
        ('dwXSize', 'DWORD'),
        ('dwYSize', 'DWORD'),
        ('dwXCountChars', 'DWORD'),
        ('dwYCountChars', 'DWORD'),
        ('dwFillAttribute', 'DWORD'),
        ('dwFlags', 'DWORD'),
        (' wShowWindow', 'WORD'),
        (' cbReserved2', 'WORD'),
        ('lpReserved2', 'LPBYTE'),
        ('hStdInput', 'HANDLE'),
        ('hStdOutput', 'HANDLE'),
        ('hStdError', 'HANDLE')
    ]
