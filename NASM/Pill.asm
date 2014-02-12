
		global  _main
        extern  _printf
		extern	_scanf
		
		SECTION .data
dilemme		db	'Take the red (1) or blue (0) pill.', 0
red			db	'You take the red pill', 0
blue		db	'You take the blue pill', 0
morpheus	db	'%d', 0
neo			db	0, 0

        SECTION .text
_main:
		push dilemme
		call _printf
		add esp, 4

		push neo
		push morpheus
		call _scanf
		add esp, 8

		mov eax, [neo]
		cmp eax, 0
		je _blue
		push red
		call _printf
		add esp, 4
		jmp _end_blue
_blue:
		push blue
		call _printf
		add esp, 4
_end_blue:
        ret		0x0
		