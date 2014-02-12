	global  _main

	SECTION .text
	next:
	mov	eax, 0x7635c5b9 ; Hard Offset 'printf' msvcrt.dll
	call	eax
	add	esp, 4
	ret	0x0

	_main:
	call	next
	db "Hello World", 0
		