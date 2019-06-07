;Decrypt the exe which is stored in input_image
proc decryptExecutable APITable:QWORD, input_image:QWORD

local str1[256]:BYTE, ret_val:QWORD,\
key[KEY_SIZE]:BYTE, encrypted_backup:QWORD

        mov [APITable],rcx
        mov [input_image],rdx
        push rdi
        push rsi
        writeWithNewLine createStringBruteforcing, str1, dec_exit_success
        
        ;init key
        lea rdi,[key]
        mov rcx, KEY_SIZE
        mov al,0
dec_init_key:
        mov [rdi],al
        inc rdi
        dec rcx
        jnz dec_init_key

        ;create a copy of the encrypted file
        ;which is used to brute force the key
        mov rax,[APITable]
        fastcall qword [rax+VirtualAlloc], 0, INFILE_SIZE, MEM_COMMIT+MEM_RESERVE, PAGE_READWRITE
        test rax, rax
        jz dec_exit_error
        mov [encrypted_backup],rax
        ;now copy the file into the buffer
        mov rdi,rax
        mov rsi,[input_image]
        mov rcx,INFILE_SIZE
        ;we can mov qwords because buffer is a multiple of 16
        shr rcx,3
        repz movsq

keyspace_loop:
        lea rax,[key]
        fastcall decAES, INFILE_SIZE, [input_image], [input_image], rax
        fastcall verifyChecksum, [input_image], INFILE_SIZE
        test rax,rax
        jnz dec_decrypted_success

        ;restore the encrypted version to try the next key
        mov rsi,[encrypted_backup]
        mov rdi,[input_image]
        mov rcx,INFILE_SIZE
        shr rcx,3
        repz movsq
        ;lea eax,[key]
        ;stdcall encAES, [section_size],  [section_address],  [section_address], eax

        ;next key
        lea rax,[key]
        fastcall nextKey, rax
        test rax,rax
        jz dec_exit_error
        ;abort if key space was explored, else continue
        jmp keyspace_loop

dec_decrypted_success:
        mov rax,[APITable]
        fastcall qword [rax+VirtualFree], [encrypted_backup], 0, MEM_RELEASE
        test rax, rax
        jz dec_exit_error

dec_exit_success:
        mov rax,1
        jmp dec_exit_ret 

dec_exit_error:
        sub rax,rax

dec_exit_ret:
        pop rsi
        pop rdi
        ret

endp

;generate next decryption key
proc nextKey key_ptr:QWORD
        mov [key_ptr],rcx

        mov rax,rcx
        mov r10,rax
        add r10,REAL_KEY_SIZE
nkey_next_element:
        inc byte [rax]
        cmp byte [rax],REAL_KEY_RANGE
        jne nkey_not_finished
        mov byte [rax],0
        inc rax
        cmp rax,r10
        je nkey_finished
        jmp nkey_next_element

nkey_not_finished:
        mov rax,1
        ret

nkey_finished:
        sub rax,rax
        ret

endp;
