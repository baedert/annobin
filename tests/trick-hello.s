	.file	"trick-hello.c"
	.text
	.section	.rodata
.LC0:
	.string	"hah, gotcha!"
	.text
	.globl	he‮oll‬
	.type	he‮oll‬, %function
he‮oll‬:
.LFB0:
	nop
.LFE0:
	.size	he‮oll‬, .-he‮oll‬
	.section	.rodata
.LC1:
	.string	"Hello world"
	.text
	.globl	hello
	.type	hello, %function
hello:
.LFB1:
	nop
.LFE1:
	.size	hello, .-hello
	.globl	main
	.type	main, %function
main:
.LFB2:
	nop
.LFE2:
	.size	main, .-main
	.ident	"GCC: (GNU) 11.2.1 20210728 (Red Hat 11.2.1-1)"
	.section	.note.GNU-stack,"",%progbits
