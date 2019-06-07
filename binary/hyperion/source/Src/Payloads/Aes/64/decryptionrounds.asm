;uses the generated round keys to decrypt an aes block
proc decryptionRounds decryption_ptr:QWORD,\
     roundkeys_ptr:QWORD, inverse_sbox_ptr:QWORD, mul9_table_ptr:QWORD, \
     mul11_table_ptr:QWORD, mul13_table_ptr:QWORD,\
     mul14_table_ptr:QWORD

    mov [decryption_ptr], rcx
    mov [roundkeys_ptr], rdx
    mov [inverse_sbox_ptr], r8
    mov [mul9_table_ptr], r9
    push rbx
    push r12

    ;roundkey and decryption in eax and ebx
    mov r12, [roundkeys_ptr]
    add r12, BLOCK_SIZE*ENCRYPTION_ROUNDS
    mov rbx, [decryption_ptr]

    ;final round
    fastcall addRoundKey, rbx, r12
    fastcall inverseShiftRows, rbx
    fastcall subBlockBytes, rbx, [inverse_sbox_ptr]
    sub r12,BLOCK_SIZE

    ;main round
dr_main:
    fastcall addRoundKey, rbx, r12
    fastcall mixColumns9111314, rbx, [mul9_table_ptr], [mul11_table_ptr],\
            [mul13_table_ptr], [mul14_table_ptr]
    fastcall inverseShiftRows, rbx
    fastcall subBlockBytes, rbx, [inverse_sbox_ptr]
    sub r12, BLOCK_SIZE
    cmp r12, [roundkeys_ptr]
    jne dr_main

    ;initial_round
    fastcall addRoundKey, rbx, r12

    pop r12
    pop rbx
    ret
endp

;mix columns operation is a column matrix
;multiplication
proc mixColumns9111314, data_ptr:QWORD, mul9_table_ptr:QWORD,\
     mul11_table_ptr:QWORD, mul13_table_ptr:QWORD, mul14_table_ptr:QWORD

    local current_column:DWORD

    mov [data_ptr],rcx
    mov [mul9_table_ptr], rdx
    mov [mul11_table_ptr], r8
    mov [mul13_table_ptr], r9
    push rbx ;16 byte alignment not neccessary because leaf function

    mov rdx, [data_ptr]
    rept 4{
    ;element 3
    mov eax, [rdx]
    mov rbx, [mul9_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov rbx, [mul13_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul11_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul14_table_ptr]
    xlatb
    xor cl, al
    mov [current_column], ecx
    ;element 2
    mov eax, [rdx]
    mov rbx, [mul13_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov rbx, [mul11_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul14_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul9_table_ptr]
    xlatb
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    mov [current_column], eax
    ;element 1
    mov eax, [rdx]
    mov rbx, [mul11_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov rbx, [mul14_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul9_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul13_table_ptr]
    xlatb
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    mov [current_column], eax
    ;element 0
    mov eax, [rdx]
    mov rbx, [mul14_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov rbx, [mul9_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul13_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul11_table_ptr]
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

;reverse shift operation for decryption
proc inverseShiftRows, data_ptr:QWORD
    push rbx ;16 byte alignment not neccessary because leaf function

    mov rbx,rcx;[data_ptr]
    loadRow
    rol eax, 8
    storeRow
    inc rbx
    loadRow
    rol eax, 16
    storeRow
    inc rbx
    loadRow
    rol eax, 24
    storeRow

    pop rbx
    ret

endp
