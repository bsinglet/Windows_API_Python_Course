"""
 Filename: display_message_box.py
 Description: Kills a process when give the window title. All code in this file
 copied from Brandon Dennis' "Hacking Windows API With Python" course on Udemy.
 Created by: Benjamin M. Singleton
 Created: 03-09-2020
"""

import ctypes

# we need the DLLs for the MessageBox to be able to use it, and kernel32 to catch errors
user_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("Kernel32.dll")

# these are the arguments for MessageBoxW
hWnd = None  # not specifying a handle for the MessageBox as it's optional
lpText = "Hello World"  # text to display in the box
lpCaption = "Hello, students"  # title of the box
uType = 0x00000001  # type is message box with OK and Cancel at bottom

# make the actual API call
response = user_handle.MessageBoxW(hWnd, lpText, lpCaption, uType)

# check for errors
error = k_handle.GetLastError()

if error != 0:
    print("Error code: {0}".format(error))
    exit(1)

# determine which button was clicked
if response == 1:
    print("User clicked okay")
elif response == 2:
    print("User clicked cancel")
else:
    print("User did something else")
