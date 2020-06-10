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
	.long	34	# size of name 
	.long	16	# description size [= 2 * sizeof (address)] 
	.long	256	# note type [256 = GLOBAL, 257 = FUNCTION] 
	.byte	71
	.byte	65
	.byte	36
	.byte	5
	.byte	114
	.byte	117
	.byte	110
	.byte	110
	.byte	105
	.byte	110
	.byte	103
	.byte	32
	.byte	111
	.byte	110
	.byte	32
	.byte	76
	.byte	76
	.byte	86
	.byte	77
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
	.byte	0	# tool note (running on) 
	.byte	0
	.byte	0	# padding 
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
	.long	13	# size of name 
	.long	16	# description size [= 2 * sizeof (address)] 
	.long	256	# note type [256 = GLOBAL, 257 = FUNCTION] 
	.byte	71
	.byte	65
	.byte	42
	.byte	70
	.byte	79
	.byte	82
	.byte	84
	.byte	73
	.byte	70
	.byte	89
	.byte	0
	.byte	1
	.byte	0	# _FORTITFY_SOURCE used (probably) 
	.byte	0
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
	.file	1 "/home/nickc/work/sources/annobin/llvm-plugin" "hello.c"
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
.Lfunc_begin0:
	.loc	1 8 0                   # hello.c:8:0
	.cfi_startproc
# %bb.0:
	.loc	1 9 16 prologue_end     # hello.c:9:16
	endbr64
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset %rbx, -16
	#DEBUG_VALUE: main:argc <- $edi
	#DEBUG_VALUE: main:argv <- $rsi
	#DEBUG_VALUE: main:argv <- $rsi
	movq	(%rsi), %rsi
.Ltmp0:
	#DEBUG_VALUE: strcpy:__src <- $rsi
	.file	2 "/usr/include/bits" "string_fortified.h"
	.loc	2 90 10                 # /usr/include/bits/string_fortified.h:90:10
	movq	buf@GOTPCREL(%rip), %rbx
.Ltmp1:
	#DEBUG_VALUE: strcpy:__dest <- $rbx
	movq	%rbx, %rdi
.Ltmp2:
	callq	strcpy@PLT
.Ltmp3:
	.loc	1 10 10                 # hello.c:10:10
	movl	$1, %edi
	movq	%rbx, %rsi
	xorl	%eax, %eax
	popq	%rbx
.Ltmp4:
	.cfi_def_cfa_offset 8
	jmp	__printf_chk@PLT        # TAILCALL
.Ltmp5:
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
                                        # -- End function
	.type	buf,@object             # @buf
	.comm	buf,128,16
	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 8.0.0 (Fedora 8.0.0-3.fc30) /usr/bin/clang-8 -Xclang -load -Xclang /home/nickc/work/sources/annobin/llvm-plugin/annobin.so -D _FORTIFY_SOURCE=2 -O2 -g -grecord-command-line -fpic -Wall -fsanitize=safe-stack -fstack-protector-strong -fcf-protection=full -fsanitize=cfi-cast-strict hello.c -save-temps=cwd" # string offset=0
.Linfo_string1:
	.asciz	"hello.c"               # string offset=318
.Linfo_string2:
	.asciz	"/home/nickc/work/sources/annobin/llvm-plugin" # string offset=326
.Linfo_string3:
	.asciz	"buf"                   # string offset=371
.Linfo_string4:
	.asciz	"char"                  # string offset=375
.Linfo_string5:
	.asciz	"__ARRAY_SIZE_TYPE__"   # string offset=380
.Linfo_string6:
	.asciz	"strcpy"                # string offset=400
.Linfo_string7:
	.asciz	"__dest"                # string offset=407
.Linfo_string8:
	.asciz	"__src"                 # string offset=414
.Linfo_string9:
	.asciz	"main"                  # string offset=420
.Linfo_string10:
	.asciz	"int"                   # string offset=425
.Linfo_string11:
	.asciz	"argc"                  # string offset=429
.Linfo_string12:
	.asciz	"argv"                  # string offset=434
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
	.quad	.Lfunc_begin0-.Lfunc_begin0
	.quad	.Ltmp2-.Lfunc_begin0
	.short	1                       # Loc expr size
	.byte	85                      # super-register DW_OP_reg5
	.quad	0
	.quad	0
.Ldebug_loc1:
	.quad	.Lfunc_begin0-.Lfunc_begin0
	.quad	.Ltmp0-.Lfunc_begin0
	.short	1                       # Loc expr size
	.byte	84                      # DW_OP_reg4
	.quad	0
	.quad	0
.Ldebug_loc2:
	.quad	.Ltmp0-.Lfunc_begin0
	.quad	.Ltmp3-.Lfunc_begin0
	.short	1                       # Loc expr size
	.byte	84                      # DW_OP_reg4
	.quad	0
	.quad	0
.Ldebug_loc3:
	.quad	.Ltmp1-.Lfunc_begin0
	.quad	.Ltmp4-.Lfunc_begin0
	.short	1                       # Loc expr size
	.byte	83                      # DW_OP_reg3
	.quad	0
	.quad	0
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
	.byte	52                      # DW_TAG_variable
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	63                      # DW_AT_external
	.byte	25                      # DW_FORM_flag_present
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	2                       # DW_AT_location
	.byte	24                      # DW_FORM_exprloc
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	3                       # Abbreviation Code
	.byte	1                       # DW_TAG_array_type
	.byte	1                       # DW_CHILDREN_yes
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	4                       # Abbreviation Code
	.byte	33                      # DW_TAG_subrange_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	55                      # DW_AT_count
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	5                       # Abbreviation Code
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
	.byte	6                       # Abbreviation Code
	.byte	36                      # DW_TAG_base_type
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	11                      # DW_AT_byte_size
	.byte	11                      # DW_FORM_data1
	.byte	62                      # DW_AT_encoding
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	7                       # Abbreviation Code
	.byte	46                      # DW_TAG_subprogram
	.byte	1                       # DW_CHILDREN_yes
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
	.byte	32                      # DW_AT_inline
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	8                       # Abbreviation Code
	.byte	5                       # DW_TAG_formal_parameter
	.byte	0                       # DW_CHILDREN_no
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	9                       # Abbreviation Code
	.byte	15                      # DW_TAG_pointer_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	10                      # Abbreviation Code
	.byte	55                      # DW_TAG_restrict_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	11                      # Abbreviation Code
	.byte	38                      # DW_TAG_const_type
	.byte	0                       # DW_CHILDREN_no
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	12                      # Abbreviation Code
	.byte	46                      # DW_TAG_subprogram
	.byte	1                       # DW_CHILDREN_yes
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
	.byte	13                      # Abbreviation Code
	.byte	5                       # DW_TAG_formal_parameter
	.byte	0                       # DW_CHILDREN_no
	.byte	2                       # DW_AT_location
	.byte	23                      # DW_FORM_sec_offset
	.byte	3                       # DW_AT_name
	.byte	14                      # DW_FORM_strp
	.byte	58                      # DW_AT_decl_file
	.byte	11                      # DW_FORM_data1
	.byte	59                      # DW_AT_decl_line
	.byte	11                      # DW_FORM_data1
	.byte	73                      # DW_AT_type
	.byte	19                      # DW_FORM_ref4
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	14                      # Abbreviation Code
	.byte	29                      # DW_TAG_inlined_subroutine
	.byte	1                       # DW_CHILDREN_yes
	.byte	49                      # DW_AT_abstract_origin
	.byte	19                      # DW_FORM_ref4
	.byte	17                      # DW_AT_low_pc
	.byte	1                       # DW_FORM_addr
	.byte	18                      # DW_AT_high_pc
	.byte	6                       # DW_FORM_data4
	.byte	88                      # DW_AT_call_file
	.byte	11                      # DW_FORM_data1
	.byte	89                      # DW_AT_call_line
	.byte	11                      # DW_FORM_data1
	.byte	0                       # EOM(1)
	.byte	0                       # EOM(2)
	.byte	15                      # Abbreviation Code
	.byte	5                       # DW_TAG_formal_parameter
	.byte	0                       # DW_CHILDREN_no
	.byte	2                       # DW_AT_location
	.byte	23                      # DW_FORM_sec_offset
	.byte	49                      # DW_AT_abstract_origin
	.byte	19                      # DW_FORM_ref4
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
	.byte	1                       # Abbrev [1] 0xb:0xf5 DW_TAG_compile_unit
	.long	.Linfo_string0          # DW_AT_producer
	.short	12                      # DW_AT_language
	.long	.Linfo_string1          # DW_AT_name
	.long	.Lline_table_start0     # DW_AT_stmt_list
	.long	.Linfo_string2          # DW_AT_comp_dir
	.quad	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	2                       # Abbrev [2] 0x2a:0x15 DW_TAG_variable
	.long	.Linfo_string3          # DW_AT_name
	.long	63                      # DW_AT_type
                                        # DW_AT_external
	.byte	1                       # DW_AT_decl_file
	.byte	4                       # DW_AT_decl_line
	.byte	9                       # DW_AT_location
	.byte	3
	.quad	buf
	.byte	3                       # Abbrev [3] 0x3f:0xc DW_TAG_array_type
	.long	75                      # DW_AT_type
	.byte	4                       # Abbrev [4] 0x44:0x6 DW_TAG_subrange_type
	.long	82                      # DW_AT_type
	.byte	128                     # DW_AT_count
	.byte	0                       # End Of Children Mark
	.byte	5                       # Abbrev [5] 0x4b:0x7 DW_TAG_base_type
	.long	.Linfo_string4          # DW_AT_name
	.byte	6                       # DW_AT_encoding
	.byte	1                       # DW_AT_byte_size
	.byte	6                       # Abbrev [6] 0x52:0x7 DW_TAG_base_type
	.long	.Linfo_string5          # DW_AT_name
	.byte	8                       # DW_AT_byte_size
	.byte	7                       # DW_AT_encoding
	.byte	7                       # Abbrev [7] 0x59:0x23 DW_TAG_subprogram
	.long	.Linfo_string6          # DW_AT_name
	.byte	2                       # DW_AT_decl_file
	.byte	88                      # DW_AT_decl_line
                                        # DW_AT_prototyped
	.long	124                     # DW_AT_type
                                        # DW_AT_external
	.byte	1                       # DW_AT_inline
	.byte	8                       # Abbrev [8] 0x65:0xb DW_TAG_formal_parameter
	.long	.Linfo_string7          # DW_AT_name
	.byte	2                       # DW_AT_decl_file
	.byte	88                      # DW_AT_decl_line
	.long	129                     # DW_AT_type
	.byte	8                       # Abbrev [8] 0x70:0xb DW_TAG_formal_parameter
	.long	.Linfo_string8          # DW_AT_name
	.byte	2                       # DW_AT_decl_file
	.byte	88                      # DW_AT_decl_line
	.long	134                     # DW_AT_type
	.byte	0                       # End Of Children Mark
	.byte	9                       # Abbrev [9] 0x7c:0x5 DW_TAG_pointer_type
	.long	75                      # DW_AT_type
	.byte	10                      # Abbrev [10] 0x81:0x5 DW_TAG_restrict_type
	.long	124                     # DW_AT_type
	.byte	10                      # Abbrev [10] 0x86:0x5 DW_TAG_restrict_type
	.long	139                     # DW_AT_type
	.byte	9                       # Abbrev [9] 0x8b:0x5 DW_TAG_pointer_type
	.long	144                     # DW_AT_type
	.byte	11                      # Abbrev [11] 0x90:0x5 DW_TAG_const_type
	.long	75                      # DW_AT_type
	.byte	12                      # Abbrev [12] 0x95:0x5e DW_TAG_subprogram
	.quad	.Lfunc_begin0           # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0 # DW_AT_high_pc
	.byte	1                       # DW_AT_frame_base
	.byte	87
	.long	.Linfo_string9          # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	7                       # DW_AT_decl_line
                                        # DW_AT_prototyped
	.long	243                     # DW_AT_type
                                        # DW_AT_external
	.byte	13                      # Abbrev [13] 0xae:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc0            # DW_AT_location
	.long	.Linfo_string11         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	7                       # DW_AT_decl_line
	.long	243                     # DW_AT_type
	.byte	13                      # Abbrev [13] 0xbd:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc1            # DW_AT_location
	.long	.Linfo_string12         # DW_AT_name
	.byte	1                       # DW_AT_decl_file
	.byte	7                       # DW_AT_decl_line
	.long	250                     # DW_AT_type
	.byte	14                      # Abbrev [14] 0xcc:0x26 DW_TAG_inlined_subroutine
	.long	89                      # DW_AT_abstract_origin
	.quad	.Ltmp0                  # DW_AT_low_pc
	.long	.Ltmp3-.Ltmp0           # DW_AT_high_pc
	.byte	1                       # DW_AT_call_file
	.byte	9                       # DW_AT_call_line
	.byte	15                      # Abbrev [15] 0xdf:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc3            # DW_AT_location
	.long	101                     # DW_AT_abstract_origin
	.byte	15                      # Abbrev [15] 0xe8:0x9 DW_TAG_formal_parameter
	.long	.Ldebug_loc2            # DW_AT_location
	.long	112                     # DW_AT_abstract_origin
	.byte	0                       # End Of Children Mark
	.byte	0                       # End Of Children Mark
	.byte	5                       # Abbrev [5] 0xf3:0x7 DW_TAG_base_type
	.long	.Linfo_string10         # DW_AT_name
	.byte	5                       # DW_AT_encoding
	.byte	4                       # DW_AT_byte_size
	.byte	9                       # Abbrev [9] 0xfa:0x5 DW_TAG_pointer_type
	.long	124                     # DW_AT_type
	.byte	0                       # End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_macinfo,"",@progbits
	.byte	0                       # End Of Macro List Mark

	.ident	"clang version 8.0.0 (Fedora 8.0.0-3.fc30)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym strcpy
	.addrsig_sym buf
	.section	.debug_line,"",@progbits
.Lline_table_start0:
