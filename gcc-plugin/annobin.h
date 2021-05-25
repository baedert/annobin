/* annobin - Header file for the gcc plugin for annotating binary files.
   Copyright (c) 2017 - 2021 Red Hat.
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

/* This structure provides various names associated with a function.
   The fields are computed in annobin_create_function_notes
   and consumed in various places.  This structure is also used
   For global data, but in this case the start and end symbols
   are NULL.  */
typedef struct annobin_function_info
{
  const char * func_name;
  const char * asm_name;
  const char * section_name;
  const char * group_name;
  bool         comdat;
  const char * note_section_declaration;
  const char * start_sym;
  const char * end_sym;
  const char * unlikely_section_name;
  const char * unlikely_end_sym;
} annobin_function_info;

enum attach_type
{
  none,
  group,
  link_order
};

/* How to connection annobin notes to code sections.  */
extern enum attach_type annobin_attach_type;

/* ------ TARGET SPECIFIC FUNCTIONS ----------------------------- */

/* Called during plugin_init().
   Should record any target specific information that will be needed later.
   Returns 0 upon success and 1 if there is a failure.  */
extern int annobin_save_target_specific_information (void);

/* Called during PLUGIN_START_UNIT.
   Returns the size of the target pointer in bits.
   Expected return values are either 32 or 64.  */
extern unsigned int annobin_get_target_pointer_size (void);

/* Called during PLUGIN_START_UNIT.
   Should only produce global, target specific notes.  */
extern void annobin_record_global_target_notes (annobin_function_info *);

/* Called during PLUGIN_ALL_PASSES_START.
   Should produce notes specific to the function just compiled.
   Arguments are the current function structure
   and a boolean indicating if it is necessary to FORCE
   the generation of notes even if nothing has changed.  */
extern void annobin_target_specific_function_notes (annobin_function_info *, bool FORCE);

/* Called during plugin_init ().
   Returns the bias, if any, that should be applied to
   the start symbol in order for it to avoid conflicts
   with file symbols and/or the first function symbol.  */
extern signed int annobin_target_start_symbol_bias (void);

/* ------ GENERIC FUNCTIONS ----------------------------- */

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
   field of the note.  It can be NULL.  It can also contain non-ASCII characters.
   NAME_LENGTH is the length of the name, including the terminating NUL.
   NAME_IS_STRING is true if NAME only contains ASCII characters.
   NAME_DESCRIPTION is a description of the name field, used in comments and
   verbose output.

   IS_OPEN is true for OPEN type notes and false for FUNC type notes.

   The INFO structure contains pointers to the START_SYM and END_SYM to be
   put into the description field of the note.  They can be NULL.

   The INFO strcuture also contains the fully qualified note section name.    */

extern void annobin_output_note (const char * NAME,
				 unsigned     NAME_LENGTH,
				 bool         NAME_IS_STRING,
				 const char * NAME_DESCRIPTION,
				 bool         IS_OPEN,
				 annobin_function_info * INFO);

extern void annobin_output_bool_note (const char   BOOL_TYPE,
				      const bool   BOOL_VALUE,
				      const char * NAME_DESCRIPTION,
				      bool         IS_OPEN,
				      annobin_function_info * INFO);

extern void annobin_output_string_note (const char   STRING_TYPE,
					const char * THE_STRING,
					const char * NAME_DESCRIPTION,
					bool         IS_OPEN,
					annobin_function_info * INFO);

extern void annobin_output_numeric_note (const char    NUMERIC_TYPE,
					 unsigned long VALUE,
					 const char *  NAME_DESCRIPTION,
					 bool          IS_OPEN,
					 annobin_function_info * INFO);

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
   minor revision.  So annobin provides the following two macros/functions to
   access these options via their OPT_<name> values:  */

extern const char *   annobin_get_str_option_by_index (int);
extern int            annobin_get_int_option_by_index (int);

#define GET_STR_OPTION_BY_INDEX(INDX) annobin_get_str_option_by_index (INDX)
#define GET_INT_OPTION_BY_INDEX(INDX) annobin_get_int_option_by_index (INDX)

/* GCC 11 introduced a new array - cl_vars - which can be used to find the
   offsets for other fields in the global_options array.  So the following
   functions/macros make use of this, if it is available.  If not then the
   original offset is used instead, although this is prone to the problem
   described above.  */

extern struct gcc_options * annobin_global_options;
extern const char *         annobin_get_str_option_by_name (const char *, const char *);
extern const int            annobin_get_int_option_by_name (const char *, const int);

#define GET_STR_OPTION_BY_NAME(NAME)	annobin_get_str_option_by_name (#NAME, annobin_global_options->x_##NAME)
#define GET_INT_OPTION_BY_NAME(NAME) 	annobin_get_int_option_by_name (#NAME, annobin_global_options->x_##NAME)

/* Finally the definition below corrupts the global_options symbol so that it
   cannot be used, even indirectly via other macros.  This means that any new
   code that accesses global_options array will be detected at compile time,
   and can be fixed to use the functions or macros above.  */

#define ANNOBIN_ILLEGAL_GLOBAL_OPTIONS 999_illegal_reference_to_global_options
#define global_options                 ANNOBIN_ILLEGAL_GLOBAL_OPTIONS       

#endif /* __ANNOBIN_H__ */
