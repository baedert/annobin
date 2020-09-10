/* annobin - Header file for the gcc plugin for annotating binary files.
   Copyright (c) 2017 - 2020 Red Hat.
   Created by Nick Clifton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#ifndef __ANNOBIN_H__
#define __ANNOBIN_H__

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

/* Needed to access some of GCC's internal structures.  */
#include "cgraph.h"
#include "target.h"
#if GCCPLUGIN_VERSION_MAJOR >= 5
#include "errors.h"
#else
#include "diagnostic-core.h"
#endif

/* Called during plugin_init().
   Returns 0 upon success and 1 if there is a failure.  */
extern int annobin_save_target_specific_information (void);

/* Called during PLUGIN_START_UNIT.
   Should only produce notes for the static tools, ie
   notes in the SECNAME section.  */
extern void annobin_record_global_target_notes (const char * SECNAME);

/* Called during PLUGIN_START_UNIT.
   Return the size of the target pointer in bits.
   Expected return values are either 32 or 64.  */
extern unsigned int annobin_get_target_pointer_size (void);

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
#define INFORM_ALWAYS        0
#define INFORM_VERBOSE       1
#define INFORM_VERY_VERBOSE  2

/* Generate an ICE error message.  */
extern void ice (const char *);

/* Called to generate a single note.  NAME is the text to go into the name
   field of the note.  NAMESZ is the length of the name, including the
   terminating NUL.  NAME_IS_STRING is true if NAME only contains ASCII
   characters.  NAME_DESCRIPTION is a description of the name field, using
   in comments and verbose output.

   FIXME: Finish comment.  */
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

/* GCC stores lots of information in the global_options structure.
   But unfortunately it is auto-magicaly constructed and the offsets of fields
   within it can change between revisions of gcc, even minor ones.  Hence it is
   not safe to access the fields via the macros defined in options.h

   For most command line options however the offset into global_options
   is held in the cl_options array, and the entries in this array only change
   when new command line options are added.  Which is rarely the case with a
   minor revision.  So annobin provides the following two functions to
   access these options via their OPT_<name> values:  */

extern int            annobin_get_gcc_int_option (int);
extern const char *   annobin_get_gcc_str_option (int);

/* For other fields in global_options, not indexed via cl_options, annobin
   provides these two macros:  */

extern struct gcc_options * annobin_global_options;

#define GET_STR_OPTION(NAME)	annobin_global_options->x_##NAME
#define GET_INT_OPTION(NAME) 	annobin_global_options->x_##NAME

/* They are still prone to failure however, for the reasons described
   above.  For the moment thereofre these macros are placeholders.
   Once there is a way to resolve this situation it can be accessed
   through them.

   Finally the definition below corrupts the global_options symbol
   so that it cannot be used, even indirectly via other macros.
   This means that any new code that accesses global_options will
   be detected right away, and can be fixed to use the functions or
   macros above.  */

#define ANNOBIN_ILLEGAL_GLOBAL_OPTIONS 999_illegal_reference_to_global_options
#define global_options                 ANNOBIN_ILLEGAL_GLOBAL_OPTIONS       

#endif /* __ANNOBIN_H__ */
