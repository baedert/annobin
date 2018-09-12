
	.text
text_start:	
	.dc.l	0
	.dc.l	2
	.dc.l	4
	.dc.l	6
text_end:
	
	.section .note.gnu.property, "a", %note
	.balign 4
	.dc.l 4 				# size of name
	.dc.l 24				# size of description
	.dc.l 0x5				# type = PROPERTY_TYPE_0
	.asciz "GNU"				# name (GNU Property Note)
	.dc.l 0xc0000002			# GNU_PROPERTY_X86_UINT32_AND_LO
	.dc.l 8					# data size
	.dc.l 1	      				# property bits
	.dc.l 0					# padding

	.dc.l 4 				# size of name
	.dc.l 24				# size of description
	.dc.l 0x5				# type = PROPERTY_TYPE_0
	.asciz "GNU"				# name (GNU Property Note)
	.dc.l 0xc0080000			# GNU_PROPERTY_X86_UINT32_OR_HI
	.dc.l 8					# data size
	.dc.l 1	      				# isa bits
	.dc.l 0					# padding
	
	
	.section .gnu.build.attributes, "", %note
	.balign 4
	.dc.l 8					# size of name
	.dc.l 16				# size of description
	.dc.l 0x100				# type = OPEN
	.dc.b 0x47, 0x41, 0x24, 0x1, 0x33, 0x70	# name (string: version)
	.dc.b 0x38, 0 	
	.quad text_start			# description (symbol name)
	.quad text_end			


