CreateFileMapping	equ 0
MapViewOfFile		equ CreateFileMapping + 8
UnmapViewOfFile 	equ MapViewOfFile     + 8
CreateFile		equ UnmapViewOfFile   + 8
CloseHandle		equ CreateFile	      + 8
GetFileSize		equ CloseHandle       + 8
DeleteFile		equ GetFileSize       + 8
GetModuleHandle 	equ DeleteFile	      + 8
VirtualAlloc		equ GetModuleHandle   + 8
VirtualProtect		equ VirtualAlloc      + 8
VirtualFree		equ VirtualProtect    + 8

SIZE_DATA_SECTION_NAME	equ 5
SIZE_CHECKSUM		equ 4
