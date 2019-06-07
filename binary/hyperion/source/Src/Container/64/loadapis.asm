;Dynamically load the needed APIs
;Strings are created on stack

;dllname: zero terminated string with dll name
;store: save the dll image base here
;Jumps to LoadLogAPIsExit if an Error Occurs
macro loadDLL dllname, store, exit
{
        lea rax,[dllname]
        invoke LoadLibrary,rax
        test rax,rax
        jz exit
        mov [store],rax
}

;functionname: zero terminated string with functions name
;dll_imagebase: imagebase of the dll
;returns: function pointer in eax
macro loadAPI functionname, dll_imagebase, exit
{
        lea rax,[functionname]
        invoke GetProcAddress,qword [dll_imagebase],rax
        test rax,rax
        jz exit
}

;Loads all necessary APISs
proc loadRegularAPIs APITable:QWORD

local str1[256]:BYTE, kernel32_imagebase:QWORD
        mov [APITable],rcx
        writeWithNewLine createStringLoading, str1, LoadRegularAPIsExit_Error

        ;Get Kernel32.Dll Imagebase
        writeWithNewLine createStringKernel32, str1, LoadRegularAPIsExit_Error
        loadDLL str1, kernel32_imagebase, LoadRegularAPIsExit_Error

        ;Load GetModuleHandle
        writeWithNewLine createStringGetModuleHandle, str1, LoadRegularAPIsExit_Error
        loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit_Error
        mov r10,[APITable]
        mov [r10+GetModuleHandle],rax

        ;Load VirtualAlloc
        writeWithNewLine createStringVirtualAlloc, str1, LoadRegularAPIsExit_Error
        loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit_Error
        mov r10,[APITable]
        mov [r10+VirtualAlloc],rax

        ;Load VirtualProtect
        writeWithNewLine createStringVirtualProtect, str1, LoadRegularAPIsExit_Error
        loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit_Error
        mov r10,[APITable]
        mov [r10+VirtualProtect],rax

        ;Load VirtualFree
        writeWithNewLine createStringVirtualFree, str1, LoadRegularAPIsExit_Error
        loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit_Error
        mov r10,[APITable]
        mov [r10+VirtualFree],rax

        mov rax,1
        ret
        
LoadRegularAPIsExit_Error:
        sub rax,rax
        ret

endp

;Loads the basic functions for log file access
proc loadLogAPIs APITable:QWORD

local str1[256]:BYTE, kernel32_imagebase:QWORD
        mov [APITable], rcx

        ;Get Kernel32.Dll Imagebase
        createStringKernel32 str1
        loadDLL str1, kernel32_imagebase, LoadLogAPIsExit_Error

        ;Load CreateFileMapping API
        createStringCreateFileMapping str1
        loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
        mov r10,[APITable]
        mov [r10+CreateFileMapping],rax

        ;Load MapViewOfFile API
        createStringMapViewOfFile str1
        loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
        mov r10,[APITable]
        mov [r10+MapViewOfFile],rax

        ;Load UnmapViewOfFile API
        createStringUnmapViewOfFile str1
        loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
        mov r10,[APITable]
        mov [r10+UnmapViewOfFile],rax

        ;Load UnmapViewOfFile API
        createStringCreateFile str1
        loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
        mov r10,[APITable]
        mov [r10+CreateFile],rax

        ;Load CloseHandle API
        createStringCloseHandle str1
        loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
        mov r10,[APITable]
        mov [r10+CloseHandle],rax

        ;Load GetFileSize API
        createStringGetFileSize str1
        loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
        mov r10,[APITable]
        mov [r10+GetFileSize],rax

        ;Load DeleteFile API
        createStringDeleteFile str1
        loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
        mov r10,[APITable]
        mov [r10+DeleteFile],rax

        ;apis loaded successfully
        mov rax,1
        ret

LoadLogAPIsExit_Error:
        sub rax,rax
        ret

endp
