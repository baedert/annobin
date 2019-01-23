/* annobin - Header file for the gcc plugin for annotating binary files.
   Copyright (c) 2017 - 2018 Red Hat.
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

/* The version of the annotation specification supported by this plugin.  */
#define SPEC_VERSION  3

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

/* Short-hand versions of the above defines.  */
#define OPEN NT_GNU_BUILD_ATTRIBUTE_OPEN
#define FUNC NT_GNU_BUILD_ATTRIBUTE_FUNC

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

/* Called during PLUGIN_ALL_PASSES_START.
   Should produce notes specific to the function just compiled.
   Should only produce notes for the static tools, ie
   notes in the .gnu.build.attributes section.
   Arguments are the START and END symbols for the function,
   the name of the note SECTION into which the notes should be
   placed and a boolean indicating if it is necessary to FORCE
   the generation of notes even if nothing has changed.  */
extern void annobin_target_specific_function_notes (const char * START,
						    const char * END,
						    const char * SECTION,
						    bool         FORCE);

/* Called during PLUGIN_FINISH_UNIT.
   Should only produce notes for the dynamic loader, ie
   notes in the .note.gnu.property section.  */
extern void annobin_target_specific_loader_notes (void);

/* Called during plugin_init ().
   Returns the bias, if any, that should be applied to
   the start symbol in order for it to avoid conflicts
   with file symbols and/or the first function symbol.  */
extern signed int annobin_target_start_symbol_bias (void);

/* Utility function to generate some output.  The first argument is a verbosity level.
   If it is zero then the output is always generated, otherwise the output is only
   generated if the level is less than or equal to the current verbosity setting.  */
extern void annobin_inform (unsigned, const char *, ...) ATTRIBUTE_PRINTF(2, 3);

/* Called to generate a single note.  NAME is the text to go into the name
   field of the note.  NAMESZ is the length of the name, including the
   terminating NUL.  NAME_IS_STRING is true if NAME only contains ASCII
   characters.  NAME_DESCRIPTION is a description of the name field, using
   in comments and verbose output.

   FIXME: Finish comment.
 */
extern void annobin_output_note (const char * NAME,
				 unsigned     NAMESZ,
				 bool         NAME_IS_STRING,
				 const char * NAME_DESCRIPTION,
				 const char * DESC1,
				 const char * DESC2,
				 unsigned     DESCSZ,
				 bool         DESC_IS_STRING,
				 unsigned     TYPE,
				 const char * SEC_NAME);

extern void annobin_output_static_note (const char *, unsigned, bool, const char *, const char *, const char *, unsigned, const char *);
extern void annobin_output_bool_note (const char, const bool, const char *, const char *, const char *, unsigned, const char *);
extern void annobin_output_string_note (const char, const char *, const char *, const char *, const char *, unsigned, const char *);

extern void annobin_output_numeric_note (const char, unsigned long, const char *, const char *, const char *, unsigned, const char *);

extern bool           annobin_is_64bit;
extern bool           annobin_enable_stack_size_notes;
extern unsigned long  annobin_total_static_stack_usage;
extern unsigned long  annobin_max_stack_size;

/* Utlity macros to make the code cleaner.  */
#define streq(a,b)	  (strcmp ((a), (b)) == 0)
#define strneq(a,b,n)	  (strncmp ((a), (b), (n)) == 0)
#define const_strneq(a,b) (strncmp ((a), (b), sizeof (b) - 1) == 0)
