"""
 Filename: open_process.py
 Description: Kills a process when give the window title. All code in this file
 copied from Brandon Dennis' "Hacking Windows API With Python" course on Udemy.
 Created by: Benjamin M. Singleton
 Created: 03-09-2020
"""

import ctypes

k_handle = ctypes.WinDLL("Kernel32.dll")

# FIX ME - update this to prompt the user for it
process_id = 0x4E8  # just the hex of the current process ID at time of coding.

# set the arguments for the OpenProcess API call
dwDesiredAccess = (0x000F0000 | 0x00100000 | 0xFFF)  # equivalent of PROCESS_ALL_ACCESS
bInheritHandle = False  # we're not spinning off other processes, so this is irrelevant
dwProcessId = process_id

# make the call
response = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

error = k_handle.GetLastError()

if error != 0:
    print("Error code: {0}".format(error))
    exit(1)

print(response)

if response <= 0:
    print("The handle was not created")
else:
    print("Handle was created")