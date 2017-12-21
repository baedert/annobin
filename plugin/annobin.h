/* annobin - Header file for the gcc plugin for annotating binary files.
   Copyright (c) 2017 Red Hat.
   Created by Nick Clifton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

/* What a mess.  All of this is so that we can include gcc-plugin.h.  */

#include <auto-host.h>
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <config.h>
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <gcc-plugin.h>

/* These are necessary so that we can call examine the target's options.  */
#include <plugin-version.h>
extern struct plugin_gcc_version gcc_version ATTRIBUTE_UNUSED;
#include <machmode.h>
#include <output.h>
#include <opts.h>
#include <toplev.h>
#include <function.h>
#include <defaults.h>
#include <tree.h>

#include <elf.h>

#if 0 /* This would be the correct thing to do if elf/common.h did not conflict with elf.h.  */
#include "elf/common.h"
#else
#define SHF_GNU_BUILD_NOTE      (1 << 20)	/* Section contains GNU BUILD ATTRIBUTE notes.  */
#define NT_GNU_PROPERTY_TYPE_0  5		/* Generated by gcc.  */

#define NT_GNU_BUILD_ATTRIBUTE_OPEN	0x100
#define NT_GNU_BUILD_ATTRIBUTE_FUNC	0x101

#define GNU_BUILD_ATTRIBUTE_TYPE_NUMERIC	'*'
#define GNU_BUILD_ATTRIBUTE_TYPE_STRING		'$'
#define GNU_BUILD_ATTRIBUTE_TYPE_BOOL_TRUE	'+'
#define GNU_BUILD_ATTRIBUTE_TYPE_BOOL_FALSE	'!'

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

/* Values used in GNU .note.gnu.property notes (NT_GNU_PROPERTY_TYPE_0).  */
#define GNU_PROPERTY_STACK_SIZE			1
#define GNU_PROPERTY_NO_COPY_ON_PROTECTED	2
#endif /* Copy of elf/common.h  */

/* Called during plugin_init().  */
extern void annobin_save_target_specific_information (void);

/* Called during PLUGIN_START_UNIT.
   Should only produce notes for the static tools, ie
   notes in the .gnu.build.attributes section.  */
extern void annobin_record_global_target_notes (void);

/* Called during PLUGIN_ALL_PASSES_END.
   Should produce notes specific to the function just compiled.
   Should only produce notes for the static tools, ie
   notes in the .gnu.build.attributes section.
   Arguments are the start and end symbols for the function.  */
extern void annobin_target_specific_function_notes (const char *, const char *);

/* Called during PLUGIN_FINISH_UNIT.
   Should only produce notes for the dynamic loader, ie
   notes in the .note.gnu.property section.  */
extern void annobin_target_specific_loader_notes (void);

extern void annobin_inform (unsigned, const char *, ...);
extern void annobin_output_note (const char *, unsigned, bool, const char *, const char *, const char *, unsigned, bool, unsigned);
extern void annobin_output_bool_note (const char, const bool, const char *, const char *, const char *, unsigned);
extern void annobin_output_string_note (const char, const char *, const char *, const char *, const char *, unsigned);
extern void annobin_output_numeric_note (const char, unsigned long, const char *, const char *, const char *, unsigned);

extern bool           annobin_is_64bit;
extern bool           annobin_enable_stack_size_notes;
extern unsigned long  annobin_total_static_stack_usage;
extern unsigned long  annobin_max_stack_size;

inline const char *
function_asm_name (void)
{
  if (current_function_decl)
    {
      tree name = DECL_ASSEMBLER_NAME (current_function_decl);
      if (name)
	return IDENTIFIER_POINTER (name);
    }
  return NULL;
}
