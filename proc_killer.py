"""
 Filename: proc_killer.py
 Description: Kills a process when give the window title. All code here written
 by me.
 NOTE-Input works through the PyCharm interpreter, but not when run from
 Powershell or Windows Command Prompt.

 Created by: Benjamin M. Singleton
 Created: 03-09-2020
"""

import ctypes


def find_window_by_name(target_window_name, user_handle, k_handle):
    """
    Finds the handle of a window, given the title of that window.
    :param target_window_name: Title of target window.
    :type target_window_name: ctypes.c_char_p
    :param user_handle: The handle for User32.DLL.
    :type user_handle: ctypes.WinDLL
    :param k_handle: The handle for Kernel32.DLL.
    :type k_handle: ctypes.WinDLL
    :return: Handle of the window.
    :rtype: ctypes.c_void_p
    """
    lpClassName = None  # optional, and we want flexibility
    lpWindowName = target_window_name
    response = user_handle.FindWindowA(lpClassName, lpWindowName)

    error = k_handle.GetLastError()

    if error != 0:
        print("Encountered error in FindWindowA call")
        print("Error code: {0}".format(error))
        exit(1)

    if response <= 0:
        print("The handle was not created")
        exit(1)
    else:
        print("Handle was created: " + str(response))

    return response


def process_id_by_window_handle(hWnd, user_handle, k_handle):
    """
    Returns the process ID of the given window.
    :param hWnd: Handle of the desired window.
    :type hWnd: ctypes.c_void_p
    :param user_handle: The handle for User32.DLL.
    :type user_handle: ctypes.WinDLL
    :param k_handle: The handle for Kernel32.DLL.
    :type k_handle: ctypes.WinDLL
    :return: The desired process ID.
    :rtype: ctypes.c_ulong
    """
    lpdwProcessId = ctypes.c_ulong()  # this is the variable for the Process Id
    response = user_handle.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))

    error = k_handle.GetLastError()

    if error != 0:
        print("Encountered error in GetWindowThreadProcessId call")
        print("Error code: {0}".format(error))
        exit(1)

    print("Window thread ID found: " + str(response))
    print("But we're throwing that away because we only want the process ID: " + str(lpdwProcessId))

    return lpdwProcessId


def open_process_by_id(process_id, k_handle):
    """
    Creates a handle for accessing the process.
    :param process_id: The process ID of the target process.
    :type process_id: ctypes.c_ulong
    :param k_handle: The handle for Kernel32.DLL.
    :type k_handle: ctypes.WinDLL
    :return: The process handle.
    :rtype: ctypes.c_void_p
    """
    dwDesiredAccess = (0x000F0000 | 0x00100000 | 0xFFF)  # equivalent of PROCESS_ALL_ACCESS
    bInheritHandle = False  # we're not spinning off other processes, so this is irrelevant
    dwProcessId = process_id

    process_handle = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

    error = k_handle.GetLastError()

    if error != 0:
        print("Encountered error in OpenProcess call")
        print("Error code: {0}".format(error))
        exit(1)

    if process_handle <= 0:
        print("The handle was not created")
        exit(1)
    else:
        print("Handle was created: " + str(process_handle))

    return process_handle


def kill_process(process_handle, k_handle):
    """
    Terminates the specified process.
    :param process_handle: The open handle used to access the process.
    :type process_handle: ctypes.c_void_p
    :param k_handle: The handle for Kernel32.DLL.
    :type k_handle: ctypes.WinDLL
    """
    hProcess = process_handle
    uExitCode = 0x1

    response = k_handle.TerminateProcess(hProcess, uExitCode)

    error = k_handle.GetLastError()

    if error != 0:
        print("Encountered error in TerminateProcess call")
        print("Error code: {0}".format(error))
        exit(1)

    if response == 0:
        print("TerminateProcess failed, yet there was no last error? Weird.")
        exit(1)

    print("Succesfully killed target process")


def main():
    # we'll use these handles in every function, they give Python access to these
    # two Windows DLLs
    user_handle = ctypes.WinDLL("User32.dll")
    k_handle = ctypes.WinDLL("Kernel32.dll")

    window_name = ctypes.c_char_p(input("Please enter the process name: ").encode('utf-8'))
    window_handle = find_window_by_name(window_name, user_handle, k_handle)
    process_id = process_id_by_window_handle(window_handle, user_handle, k_handle)
    process_handle = open_process_by_id(process_id, k_handle)
    kill_process(process_handle, k_handle)


if __name__ == '__main__':
    main()
