;-------------------------------------------
;the content of this file is excluded,      |
;when the user disables logging features    |
;in hyperion command line. pls keep in mind |
;and dont rely on its existence.            |
;-------------------------------------------  

;--- Begin Macro Section ---

;writes a string and a newline to the logfile
macro writeWithNewLine char_sequence, char_buffer, error_exit{
        char_sequence char_buffer
        lea rax,[str1]
        fastcall writeLog_,[APITable],rax
        test rax,rax
        jz error_exit
        fastcall writeNewLineToLog_,[APITable]
        test rax,rax
        jz error_exit
}

;write a string to the logfile
macro writeLog apitable, content{
        fastcall writeLog_,[apitable], content
}

;delete old log file and create a new one
macro initLogFile apitable{
        fastcall initLogFile_, [apitable]
}

;write a newline into logfile
macro writeNewLineToLog apitable{
        fastcall writeNewLineToLog_, [apitable]
}

;write a register value into logile
macro writeRegisterToLog apitable, value{
        fastcall writeRegisterToLog_, [apitable], value
}

;--- End Macro Section ---

;get the length of a string
proc strlen_ string_ptr:QWORD

         mov [string_ptr],rcx
         push rdi
         push rcx

         mov rdi,[string_ptr]
         sub rcx, rcx
         sub al, al
         not rcx
         cld
         repne scasb
         not rcx
         dec rcx
         mov rax,rcx

         pop rcx
         pop rdi
         ret

endp

;write <content> into log.txt
;returns false if an eerror occurs
proc writeLog_ APITable:QWORD, content:QWORD

local str1[256]:BYTE, oldlogsize:QWORD, newlogsize:QWORD, contentsize:QWORD,\
      filehandle:QWORD, filemappingobject:QWORD, mapaddress:QWORD, retval:QWORD

         mov [APITable],rcx
         mov [content],rdx

         ;open file
         createStringLogTxt str1
         mov rax,[APITable]
         lea r10,[str1]
         sub r11,r11
         fastcall qword [rax+CreateFile], r10, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, r11, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, r11
         mov [retval],rax
         test rax,rax
         jz wl_logexit
         mov [filehandle],rax

         ;get logfile size
         mov rax,[APITable]
         fastcall qword [rax+GetFileSize], qword [filehandle], 0
         mov [oldlogsize],rax

         ;get size of string for logfile for concatenation
         fastcall strlen_, qword [content]
         mov [contentsize], rax
         add rax,qword [oldlogsize]
         mov [newlogsize], rax

         ;create the file mapping
         sub r10,r10
         mov r11,[APITable]
         fastcall qword [r11+CreateFileMapping], qword [filehandle], r10, PAGE_READWRITE, r10, rax, r10
         mov [retval],rax
         test rax, rax
         jz wl_closelogfile
         mov [filemappingobject],rax

         sub r10,r10
         mov r11,[APITable]
         fastcall qword [r11+MapViewOfFile], rax, FILE_MAP_ALL_ACCESS, r10, r10, qword [newlogsize]
         mov [retval],rax
         test rax, rax
         jz wl_closemaphandle
         mov [mapaddress],rax

         ;copy string into map
         add rax,[oldlogsize]
         mov rdi,rax
         mov rsi,[content]
         mov rcx,[contentsize]
         repz movsb
         mov [retval],1

wl_unmapfile:
         mov rax,[APITable]
         fastcall qword [rax+UnmapViewOfFile], qword [mapaddress]

wl_closemaphandle:
         mov rax,[APITable]
         fastcall qword [rax+CloseHandle], qword [filemappingobject]

wl_closelogfile:
         mov rax,[APITable]
         fastcall qword [rax+CloseHandle], qword [filehandle]

wl_logexit:
         mov rax,[retval]
         ret;

endp

;adds a <newline> to the logfile
;returns false if an error occurs
proc writeNewLineToLog_ APITable:QWORD

local str1[3]:BYTE
         mov [APITable],rcx

         lea rax,[str1]
         mov byte [rax+0],13
         mov byte [rax+1],10
         mov byte [rax+2],0
         fastcall writeLog_, [APITable], rax
         ret

endp

;returns false if an error occurs
proc writeRegisterToLog_ APITable:QWORD, Value:QWORD

local str1[18]:BYTE, retval:QWORD
         mov [APITable],rcx
         mov [Value],rdx

         lea rax,[str1]
         fastcall binToString_, rax, [Value]
         fastcall writeLog_,[APITable],rax
         mov [retval],rax
         test rax,rax
         jz wrtl_exit
         fastcall writeNewLineToLog_,[APITable]
         mov [retval],rax
         test rax,rax
         jz wrtl_exit

wrtl_exit:
         mov rax,[retval]
         ret

endp

;converts <bin> into an 8 byte string and stores it <buffer>
proc binToString_ buffer:QWORD, bin:QWORD
         mov [buffer],rcx
         mov [bin], rdx

         mov r10,[bin]
         mov rcx,16
bts_next_byte:
         mov rax,r10
         and rax,0000000fh
         cmp rax,9
         jg bts_add_55
bts_add_48:
         add rax,48
         jmp bts_store_bin
bts_add_55:
         add rax,55
bts_store_bin:
         dec rcx
         mov rdx,[buffer]
         mov byte [rcx+rdx],al
         test rcx,rcx
         jz bts_finished_conversion
         shr r10,4
         jmp bts_next_byte

bts_finished_conversion:
         mov rax,[buffer]
         mov byte [rax+16],0
         ret
endp

;Write initial message into logfile
proc initLogFile_ APITable:QWORD

local str1[256]:BYTE

        mov [APITable], rcx

        createStringLogTxt str1
        mov rax,[APITable]
        lea r10,[str1]
        fastcall qword [rax+DeleteFile],r10

        createStringStartingHyperionLines str1
        lea r10,[str1]
        fastcall writeLog_,[APITable],r10
        test rax,rax
        jz ilf_exit_error

        createStringStartingHyperion str1
        lea r10,[str1]
        fastcall writeLog_,[APITable],r10
        test rax,rax
        jz ilf_exit_error

        createStringStartingHyperionLines str1
        lea r10,[str1]
        fastcall writeLog_,[APITable],r10
        test rax,rax
        jz ilf_exit_error

        fastcall writeNewLineToLog_,[APITable]
        test rax,rax
        jz ilf_exit_error

ilf_exit_success:
        mov rax,1
        ret

ilf_exit_error:
        sub rax,rax
        ret

endp
