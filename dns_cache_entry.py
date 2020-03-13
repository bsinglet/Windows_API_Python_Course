"""
 Filename: dns_cache_entry.py
 Description: Retrieves the currently cached DNS entries. All code in this file
 copied from Brandon Dennis' "Hacking Windows API With Python" course on Udemy.
 Created by: Benjamin M. Singleton
 Created: 03-12-2020
"""

import ctypes

from ctypes.wintypes import DWORD, HANDLE, LPWSTR

k_handle = ctypes.WinDLL('Kernel32.dll')
d_handle = ctypes.WinDLL('DNSAPI.dll')

class DNS_CACHE_ENTRY(ctypes.Structure):
    _fields_ = [
        ('pNext', HANDLE),  # these are linked list entries, so pNext points to the next DNS_CACHE_ENTRY
        ('recName', LPWSTR),  # this is where the name of the DNS request will go
        ('wType', DWORD),
        ('wDataLength', DWORD),
        ('dwFlags', DWORD)
    ]

DNS_Entry = DNS_CACHE_ENTRY()

DNS_Entry.wDataLength = 1024  # we shouldn't need more data than that

# get the DNS Cache entries
response = d_handle.DnsGetCacheDataTable(ctypes.byref(DNS_Entry))

if response == 0:
    print('Error Code: {0}'.format(k_handle.GetLastError()))

# we don't need the first DNS entry, so we're skipping to the next
DNS_Entry = ctypes.cast(DNS_Entry.pNext, ctypes.POINTER(DNS_CACHE_ENTRY))

# iterate through the list of returned DNS entries
while True:
    try:
        print('DNS Entry {0} - Type {1}'.format(DNS_Entry.contents.recName, DNS_Entry.contents.wType))
        DNS_Entry = ctypes.cast(DNS_Entry.pNext, ctypes.POINTER(DNS_CACHE_ENTRY))
    except:
        break
