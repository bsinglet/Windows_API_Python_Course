# Windows_API_Python_Course
Notes and projects created while completing Brandon Dennis' "Hacking Windows API With Python" course on Udemy.

## Projects:
- proc_killer.py - A tool that kills the process running a given Window.
- impersonation_tool.py - A tool that spawns a new command shell running as another user. Target user is determined by giving the title of a window running under that user.

## References:
- common_structs.py - A collection of all Windows API structs that I've translated to Python (with ctypes).

## Examples:
- display_message_box_w.py - Creates a pop-up message box with Ok and Cancel buttons, and reads the user's actions on them.
- open_process.py - Opens an unprivileged handle to a running process, given a process ID.
- create_process_w.py - Spawns a new process of cmd.exe and opens the associated window.
- dns_cache_entry.py - An example of an undocumented Windows API call, reads the current DNS cache.
- open_process_token.py - Takes a window title and gets a handle to the associated process token.
- check_token_privileges.py - Checks if a running process has the security privilege SEDebugPrivilege enabled in its process token.
- modify_token_privileges.py - Lets the user interactively lookup and then toggle any privileges they want in a running process' token. 
