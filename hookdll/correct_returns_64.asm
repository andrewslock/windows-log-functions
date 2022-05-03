; Universal fake function for x64

PUBLIC correct_return_64

.code

correct_return_64 PROC

mov ax, 1
add ax, 1
add ax, 2
add ax, 3
ret

correct_return_64 ENDP

END