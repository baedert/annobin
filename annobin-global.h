/* annobin - Header file for the annobin package.
   Copyright (c) 2019 - 2021 Red Hat.
   Created by Nick Clifton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#ifdef __cplusplus
extern "C" {
#endif

/* The version of the package.

   NB/ This number is expected to be in the form "NNnn" where
   "NN" is major version number and "nn" is the minor version number.

   NB/ Keep this value in sync with libannochck_version defined in
   annocheck/libannocheck.h.  */
#define ANNOBIN_VERSION 1041

/* The version of the annotation specification supported.  */
#define SPEC_VERSION  3

#if 0 /* This would be the correct thing to do if elf/common.h did not conflict with elf.h.  */
#include "elf/common.h"
#else
#define NT_GNU_PROPERTY_TYPE_0  5		/* Note type for notes generated by gcc.  */

#define GNU_PROPERTY_AARCH64_FEATURE_1_AND	0xc0000000
#define GNU_PROPERTY_AARCH64_FEATURE_1_BTI	(1U << 0)
#define GNU_PROPERTY_AARCH64_FEATURE_1_PAC	(1U << 1)
#define DT_AARCH64_BTI_PLT	                (DT_LOPROC + 1)
#define DT_AARCH64_PAC_PLT	                (DT_LOPROC + 3)
  
#define NT_GNU_BUILD_ATTRIBUTE_OPEN	0x100
#define NT_GNU_BUILD_ATTRIBUTE_FUNC	0x101
/* Short-hand versions of the above defines.  */
#define OPEN NT_GNU_BUILD_ATTRIBUTE_OPEN
#define FUNC NT_GNU_BUILD_ATTRIBUTE_FUNC

#define GNU_BUILD_ATTRIBUTE_TYPE_NUMERIC	'*'
#define GNU_BUILD_ATTRIBUTE_TYPE_STRING		'$'
#define GNU_BUILD_ATTRIBUTE_TYPE_BOOL_TRUE	'+'
#define GNU_BUILD_ATTRIBUTE_TYPE_BOOL_FALSE	'!'

#define NUMERIC GNU_BUILD_ATTRIBUTE_TYPE_NUMERIC
#define STRING  GNU_BUILD_ATTRIBUTE_TYPE_STRING
#define BOOL_T  GNU_BUILD_ATTRIBUTE_TYPE_BOOL_TRUE
#define BOOL_F  GNU_BUILD_ATTRIBUTE_TYPE_BOOL_FALSE

#define GNU_BUILD_ATTRIBUTE_VERSION	1
#define GNU_BUILD_ATTRIBUTE_STACK_PROT	2
#define GNU_BUILD_ATTRIBUTE_RELRO	3
#define GNU_BUILD_ATTRIBUTE_STACK_SIZE	4
#define GNU_BUILD_ATTRIBUTE_TOOL	5
#define GNU_BUILD_ATTRIBUTE_ABI		6
#define GNU_BUILD_ATTRIBUTE_PIC		7
#define GNU_BUILD_ATTRIBUTE_SHORT_ENUM	8

#define NOTE_GNU_PROPERTY_SECTION_NAME	".note.gnu.property"
#define GNU_BUILD_ATTRS_SECTION_NAME	".gnu.build.attributes"

/* Characters used in the GNU_BUILD_ATTRIBUTE_VERSION note to identify the code producer.  */
#define ANNOBIN_TOOL_ID_CLANG       'L'
#define ANNOBIN_TOOL_ID_LLVM        'V'
#define ANNOBIN_TOOL_ID_ASSEMBLER   'a'
#define ANNOBIN_TOOL_ID_LINKER      'l'
#define ANNOBIN_TOOL_ID_GCC         'p'
#define ANNOBIN_TOOL_ID_GCC_COLD    'c'
#define ANNOBIN_TOOL_ID_GCC_HOT     'h'
#define ANNOBIN_TOOL_ID_GCC_STARTUP 's'
#define ANNOBIN_TOOL_ID_GCC_EXIT    'e'
#define ANNOBIN_TOOL_ID_GCC_LTO     'g'

/* Values used in GNU .note.gnu.property notes (NT_GNU_PROPERTY_TYPE_0).  */
#define GNU_PROPERTY_STACK_SIZE			1
#define GNU_PROPERTY_NO_COPY_ON_PROTECTED	2
#endif /* Copy of elf/common.h  */

/* Utlity macros to make the code cleaner.  */
#define streq(a,b)	  (strcmp ((a), (b)) == 0)
#define strneq(a,b,n)	  (strncmp ((a), (b), (n)) == 0)
#define const_strneq(a,b) (strncmp ((a), (b), sizeof (b) - 1) == 0)

#ifdef __cplusplus
}
#endif

