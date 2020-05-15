	.text
	.section	.note.gnu.property,"a",@note
	.p2align	3
	.long	4
	.long	16
	.long	5
	.asciz	"GNU"
	.long	3221225474
	.long	4
	.long	3
	.p2align	3
.Lsec_end0:
	.text
	.file	"hello.c"
                                        # Start of file scope inline assembly
	.hidden	_annobin_hello_c_start
	.type	_annobin_hello_c_start,@notype
.set _annobin_hello_c_start, .text
	.size	_annobin_hello_c_start, 0
	.section	.text.zzz,"ax",@progbits
	.hidden	_annobin_hello_c_end
	.type	_annobin_hello_c_end,@notype
.set _annobin_hello_c_end, .text.zzz
	.size	_annobin_hello_c_end, 0
	.text

	.section	.gnu.build.attributes,"",@note
	.p2align	2
	.long	10	# size of name 
	.long	16	# description size [= 2 * sizeof (address)] 
	.long	256	# note type [256 = GLOBAL, 257 = FUNCTION] 
	.byte	71
	.byte	65
	.byte	36
	.byte	1
	.byte	51
	.byte	86
	.byte	57
	.byte	50
	.byte	50
	.byte	0	# version note 
	.byte	0
	.byte	0	# padding 
	.quad	_annobin_hello_c_start	# start symbol 
	.quad	_annobin_hello_c_end	# end symbol 
	.text



	.section	.gnu.build.attributes,"",@note
	.p2align	2
	.long	40	# size of name 
	.long	16	# description size [= 2 * sizeof (address)] 
	.long	256	# note type [256 = GLOBAL, 257 = FUNCTION] 
	.byte	71
	.byte	65
	.byte	36
	.byte	5
	.byte	97
	.byte	110
	.byte	110
	.byte	111
	.byte	98
	.byte	105
	.byte	110
	.byte	32
	.byte	98
	.byte	117
	.byte	105
	.byte	108
	.byte	116
	.byte	32
	.byte	98
	.byte	121
	.byte	32
	.byte	108
	.byte	108
	.byte	118
	.byte	109
	.byte	32
	.byte	118
	.byte	101
	.byte	114
	.byte	115
	.byte	105
	.byte	111
	.byte	110
	.byte	32
	.byte	56
	.byte	46
	.byte	48
	.byte	46
	.byte	48
	.byte	0	# tool note (plugin built by) 
	.quad	_annobin_hello_c_start	# start symbol 
	.quad	_annobin_hello_c_end	# end symbol 
	.text



	.section	.gnu.build.attributes,"",@note
	.p2align	2
	.long	6	# size of name 
	.long	16	# description size [= 2 * sizeof (address)] 
	.long	256	# note type [256 = GLOBAL, 257 = FUNCTION] 
	.byte	71
	.byte	65
	.byte	42
	.byte	7
	.byte	2
	.byte	0	# PIE 
	.byte	0
	.byte	0	# padding 
	.quad	_annobin_hello_c_start	# start symbol 
	.quad	_annobin_hello_c_end	# end symbol 
	.text



	.section	.gnu.build.attributes,"",@note
	.p2align	2
	.long	10	# size of name 
	.long	16	# description size [= 2 * sizeof (address)] 
	.long	256	# note type [256 = GLOBAL, 257 = FUNCTION] 
	.byte	71
	.byte	65
	.byte	42
	.byte	71
	.byte	79
	.byte	87
	.byte	0
	.byte	0
	.byte	4
	.byte	0	# Optimization Level 
	.byte	0
	.byte	0	# padding 
	.quad	_annobin_hello_c_start	# start symbol 
	.quad	_annobin_hello_c_end	# end symbol 
	.text



	.section	.gnu.build.attributes,"",@note
	.p2align	2
	.long	20	# size of name 
	.long	16	# description size [= 2 * sizeof (address)] 
	.long	256	# note type [256 = GLOBAL, 257 = FUNCTION] 
	.byte	71
	.byte	65
	.byte	42
	.byte	99
	.byte	102
	.byte	95
	.byte	112
	.byte	114
	.byte	111
	.byte	116
	.byte	101
	.byte	99
	.byte	116
	.byte	105
	.byte	111
	.byte	110
	.byte	0
	.byte	4
	.byte	4
	.byte	0	# Control Flow protection 
	.quad	_annobin_hello_c_start	# start symbol 
	.quad	_annobin_hello_c_end	# end symbol 
	.text




                                        # End of file scope inline assembly
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
.Lfunc_begin0:
	.file	1 "/home/nickc/work/sources/annobin/llvm-plugin" "hello.c"
	.loc	1 5 0                   # hello.c:5:0
	.cfi_startproc
# %bb.0:
	.loc	1 6 10 prologue_end     # hello.c:6:10
	endbr64
	leaq	.L.str(%rip), %rdi
	xorl	%eax, %eax
	jmp	printf@PLT              # TAILCALL
.Ltmp0:
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"hello world\n"
	.size	.L.str, 13

	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 8.0.0 (Fedora 8.0.0-3.fc30) /usr/bin/clang-8 -Xclang -load -Xclang /home/nickc/work/sources/annobin/llvm-plugin/annobin.so -D _FORTIFY_SOURCE=2 -O2 -g -grecord-command-line -fpic -Wall -fsanitize=safe-stack -fstack-protector-strong -fcf-protection=full -fsanitize=cfi-cast-strict hello.c -save-temps=cwd" # string offset=0
.Linfo_string1:
	.asciz	"hello.c"               # string offset=318
.Linfo_string2:
	.asciz	"/home/nickc/work/sources/annobin/llvm-plugin" # string offset=326
.Linfo_string3:
	.asciz	"main"                  # string offset=371
.Linfo_string4:
	.asciz	"int"                   # string offset=376
	.section	.debug_abbrev,"",@progbits
	.byte	1                       # Abbreviation Code
	.byte	17                      # DW_TAG_compile_unit
	.byte	1                       # DW_CHILDREN_yes
	.byte	37                      # DW_AT_producer
	.byte	14                      # DW_FORM_strp
	.byte	19                      # DW_AT_language
	.byte	5                       # DW_FORM_data2
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	16                      # DW_AT_stmt_list
	.byte	23                      # DW_FORM_sec_offset
	.byte	27                      # DW_AT_comp_dir
	.byte	14                      # DW_FORM_strp
	.byte	17                      # DW_AT_low_pc
	.byte	1                       # DW_FORM_addr
	.byte	18                      # DW_AT_high_pc
	.byte	6                       # DW_FORM_data4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	2                       # Abbreviation Code
	.byte	46                      # DW_TAG_subprogram
	.byte	0                       # DW_CHILDREN_no
	.byte	17                      # DW_AT_low_pc
	.byte	1                       # DW_FORM_addr
	.byte	18                      # DW_AT_high_pc
	.byte	6                       # DW_FORM_data4
	.byte	64                      # DW_AT_frame_base
	.byte	24                      # DW_FORM_exprloc
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	39                      # DW_AT_prototyped
	.byte	25                      # DW_FORM_flag_present
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	63                      # DW_AT_external
	.byte	25                      # DW_FORM_flag_present
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	3                       # Abbreviation Code
	.byte	36                      # DW_TAG_base_type
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	62                      # DW_AT_encoding
	.byte	11                      # DW_FORM_data1
	.byte	11                      # DW_AT_byte_size
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	0                       # EOM(3)
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.long	.Ldebug_info_end0-.Ldebug_info_start0 # Length of Unit
.Ldebug_info_start0:
	.short	4                       # DWARF version number
	.long	.debug_abbrev           # Offset Into Abbrev. Section
	.byte	8                       # Address Size (in bytes)
	.byte	1                       # Abbrev [1] 0xb:0x40 DW_TAG_compile_unit
	.long	.Linfo_string0          # DW_AT_producer
	.short	12                      # DW_AT_language
	.long	.Linfo_string1          # DW_AT_name
	.long	.Lline_table_start0     # DW_AT_stmt_list
	.long	.Linfo_string2          # DW_AT_comp_dir
	.quad	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	2                       # Abbrev [2] 0x2a:0x19 DW_TAG_subprogram
	.quad	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	87
	.long	.Linfo_string3          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	4                       # DW_AT_decl_line
                                        # DW_AT_prototyped
	.long	67                      # DW_AT_type
                                        # DW_AT_external
	.byte	3                       # Abbrev [3] 0x43:0x7 DW_TAG_base_type
	.long	.Linfo_string4          # DW_AT_name
	.byte	5                       # DW_AT_encoding
	.byte	4                       # DW_AT_byte_size
	.byte	0                       # End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_macinfo,"",@progbits
	.byte	0                       # End Of Macro List Mark

	.ident	"clang version 8.0.0 (Fedora 8.0.0-3.fc30)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.section	.debug_line,"",@progbits
.Lline_table_start0:
