;uses the generated round keys to encrypt an aes block
proc encryptionRounds encryption_ptr:DWORD,\
     roundkeys_ptr:QWORD, sbox_ptr:QWORD, mul2_table_ptr:QWORD, \
     mul3_table_ptr:QWORD

    mov [encryption_ptr],rcx
    mov [roundkeys_ptr],rdx
    mov [sbox_ptr],r8
    mov [mul2_table_ptr],r9
    push rbx
    push r12

    ;roundkey and encryption in eax and ebx
    mov r12,[roundkeys_ptr]
    mov rbx,[encryption_ptr]

    ;initial round
    fastcall addRoundKey, rbx, r12

    ;main round
    add r12,BLOCK_SIZE
    mov rcx,ENCRYPTION_ROUNDS - 1
er_main:
    fastcall subBlockBytes, rbx, [sbox_ptr]
    fastcall shiftRows, rbx
    fastcall mixColumns23, rbx, [mul2_table_ptr], [mul3_table_ptr]
    fastcall addRoundKey, rbx, r12

    add r12,BLOCK_SIZE
    dec rcx
    jnz er_main

    ;final round
    fastcall subBlockBytes, rbx, [sbox_ptr]
    fastcall shiftRows, rbx
    fastcall addRoundKey, rbx, r12

    pop r12
    pop rbx
    ret
endp

;mix columns operation is a column matrix
;multiplication
proc mixColumns23, data_ptr:QWORD, mul2_table_ptr:QWORD,\
     mul3_table_ptr:QWORD

     local current_column:DWORD

    mov [data_ptr],rcx
    mov [mul2_table_ptr],rdx
    mov [mul3_table_ptr],r8
    push rbx
        
    mov rdx, [data_ptr]
    rept 4{
    ;element 3
    mov eax, [rdx]
    mov cl, al
    shr eax,8
    xor cl, al
    shr eax,8
    mov rbx, [mul3_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul2_table_ptr]
    xlatb
    xor cl, al
    mov [current_column], ecx
    ;element 2
    mov eax, [rdx]
    mov cl, al
    shr eax, 8
    mov rbx, [mul3_table_ptr]
    xlatb
    xor cl, al
    shr eax, 8
    mov rbx, [mul2_table_ptr]
    xlatb
    xor cl, al
    shr eax, 8
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    mov [current_column], eax
    ;element 1
    mov eax, [rdx]
    mov rbx, [mul3_table_ptr]
    xlatb
    mov cl, al
    shr eax, 8
    mov rbx, [mul2_table_ptr]
    xlatb
    xor cl, al
    shr eax, 8
    xor cl, al
    shr eax, 8
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    mov [current_column], eax
    ;element 0
    mov eax, [rdx]
    mov rbx, [mul2_table_ptr]
    xlatb
    mov cl, al
    shr eax, 8
    xor cl, al
    shr eax, 8
    xor cl, al
    shr eax, 8
    mov rbx, [mul3_table_ptr]
    xlatb
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    ;finished, store it
    mov [rdx], eax
    add rdx, COLUMN_SIZE
    }

    pop rbx
    ret

endp

;shifts the rows as desrcibed in the AES specification
;the shift process is in the reversed order because of the
;endiannes
macro loadRow{
    mov al, byte [rbx+00]
    shl eax,8
    mov al, byte [rbx+04]
    shl eax,8
    mov al, byte [rbx+08]
    shl eax,8
    mov al, byte [rbx+12]
}

macro storeRow{
    mov byte [rbx+12], al
    shr eax,8
    mov byte [rbx+08], al
    shr eax,8
    mov byte [rbx+04], al
    shr eax,8
    mov byte [rbx+00], al
}

proc shiftRows, data_ptr:DWORD

    push rax
    push rbx
    mov ebx,[data_ptr]

    loadRow
    rol eax, 24
    storeRow
    inc ebx
    loadRow
    rol eax, 16
    storeRow
    inc ebx
    loadRow
    rol eax, 8
    storeRow

    pop rbx
    pop rax
    ret

endp

;xors the data with the round key and stores result
;in data
proc addRoundKey data_ptr:QWORD, round_key_ptr:QWORD

    mov r8,[rcx]
    xor r8,[rdx]
    mov [rcx],r8
    add rcx,COLUMN_SIZE*2
    add rdx,COLUMN_SIZE*2
    mov r8,[rcx]
    xor r8,[rdx]
    mov [rcx],r8
    ret

endp

;substitute aes block with s-box
proc subBlockBytes data_ptr:QWORD, sbox_ptr:QWORD
    push rbx

    mov rbx,rdx ;sbox
    rept 2{
         mov rax,[rcx] ;data_ptr
         xlatb
         ror rax, 8
         xlatb
         ror rax, 8
         xlatb
         ror rax, 8
         xlatb
         ror rax, 8
         xlatb
         ror rax, 8
         xlatb
         ror rax, 8
         xlatb
         ror rax, 8
         xlatb
         ror rax, 8
         mov [rcx], rax
         add rcx,COLUMN_SIZE*2
    }

    pop rbx
    ret

endp
