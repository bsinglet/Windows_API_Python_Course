"""
 Filename: create_process_w.py
 Description: Creates a new command prompt window. All code in this file copied
from Brandon Dennis' "Hacking Windows API With Python" course on Udemy.
 Created by: Benjamin M. Singleton
 Created: 03-11-2020
"""

import ctypes
from ctypes.wintypes import HANDLE,DWORD,LPSTR,WORD,LPBYTE

k_handle = ctypes.WinDLL("Kernel32.dll")

# structure for Startup Info
class STARTUPINFOA(ctypes.Structure):
    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', LPSTR),
        ('lpDesktop', LPSTR),
        ('lpTitle', LPSTR),
        ('dwX', DWORD),
        ('dwY', DWORD),
        ('dwXSize', DWORD),
        ('dwYSize', DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags', DWORD),
        ('wShowWindow', WORD),
        ('cbReserved2', WORD),
        ('lpReserved2', LPBYTE),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE)
    ]

# structure for Process Info
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD)
    ]

lpApplicationName = "C:\\Windows\\System32\\cmd.exe"  # this is the program we're running
lpCommandLine = None  # no arguments
lpProcessAttributes = None
lpThreadAttributes = None
lpEnvironment = None
lpCurrentDirectory = None  # will just use current directory of this script

dwCreationFlags = 0x00000010  # means CREATE_NEW_CONSOLE, so spawn a new command window

bInheritHandle = False

lpProcessInformation = PROCESS_INFORMATION()

lpStartupInfo = STARTUPINFOA()

lpStartupInfo.wShowWindow = 0x1  # 0x1 == show normal size, 0x3 == maximize

lpStartupInfo.dwFlags = 0x1  # have to set this flag for the API to check the wShowWindow setting

response = k_handle.CreateProcessW(
    lpApplicationName,
    lpCommandLine,
    lpProcessAttributes,
    lpThreadAttributes,
    bInheritHandle,
    dwCreationFlags,
    lpEnvironment,
    lpCurrentDirectory,
    ctypes.byref(lpStartupInfo),  # this argument is a pointer to a struct, so you use byref
    ctypes.byref(lpProcessInformation))

if response > 0:
    print("Proc Is Running")
else:
    print("Failed. Error Code: {0}".format(k_handle.GetLastError()))

while True:
    continue
