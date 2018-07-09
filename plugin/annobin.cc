/* annobin - a gcc plugin for annotating binary files.
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

#include "annobin.h"

#include <stdarg.h>
#include <stdio.h>
#include <intl.h>

/* The version of the annotation specification supported by this plugin.  */
#define SPEC_VERSION  3

/* Prefix used to isolate annobin symbols from program symbols.  */
#define ANNOBIN_SYMBOL_PREFIX ".annobin_"

/* Required by the GCC plugin API.  */
int            plugin_is_GPL_compatible;

/* True if this plugin is enabled.  Disabling is permitted so that build
   systems can globally enable the plugin, and then have specific build
   targets that disable the plugin because they do not want it.  */
static bool    enabled = true;

/* True if the symbols used to map addresses to file names should be global.
   On some architectures these symbols have to be global so that they will
   be preserved in object files.  But doing so can prevent the build-id
   mechanism from working, since the symbols contain build-date information.  */
static bool    global_file_name_symbols = false;

/* True if notes about the stack usage should be included.  Doing can be useful
   if stack overflow problems need to be diagnosed, but they do increase the size
   of the note section quite a lot.  */
bool           annobin_enable_stack_size_notes = false;
unsigned long  annobin_total_static_stack_usage = 0;
unsigned long  annobin_max_stack_size = 0;

/* If a function's static stack size requirement is greater than STACK_THRESHOLD
   then a function specific note will be generated indicating the amount of stack
   that it needs.  */
#define DEFAULT_THRESHOLD (10240)
static unsigned long  stack_threshold = DEFAULT_THRESHOLD;

/* Internal variable, used by target specific parts of the annobin plugin as well
   as this generic part.  True if the object file being generated is for a 64-bit
   target.  */
bool                  annobin_is_64bit = false;

/* True if the creation of function specific notes should be reported.  */
static bool           annobin_function_verbose = false;

/* True if notes in the .note.gnu.property section should be produced.  */
static bool           annobin_enable_dynamic_notes = true;

/* True if notes in the .gnu.build.attributes section should be produced.  */
static bool           annobin_enable_static_notes = true;

#ifdef flag_stack_clash_protection
static int            global_stack_clash_option = -1;
#endif
#ifdef flag_cf_protection
static int            global_cf_option = -1;
#endif
static signed int     target_start_sym_bias = 0;
static unsigned int   annobin_note_count = 0;
static unsigned int   global_GOWall_options = 0;
static int            global_stack_prot_option = 0;
static int            global_pic_option = 0;
static int            global_short_enums = 0;
static char *         compiler_version = NULL;
static unsigned       verbose_level = 0;
static char *         annobin_current_filename = NULL;
static char *         annobin_current_endname  = NULL;
static unsigned char  annobin_version = 8; /* NB. Keep in sync with version_string below.  */
static const char *   version_string = N_("Version 8");
static const char *   help_string =  N_("Supported options:\n\
   disable                Disable this plugin\n\
   enable                 Enable this plugin\n\
   help                   Print out this information\n\
   version                Print out the version of the plugin\n\
   verbose                Be talkative about what is going on\n\
   function-verbose       Report the creation of function specific notes\n\
   [no-]dynamic-notes     Do [do not] create dynamic notes (default: do)\n\
   [no-]static-notes      Do [do not] create static notes (default: do)\n\
   [no-]global-file-syms  Create global [or local] file name symbols (default: local)\n\
   [no-]stack-size-notes  Do [do not] create stack size notes (default: do not)\n\
   stack-threshold=N      Only create function specific stack size notes when the size is > N.");

static struct plugin_info annobin_info =
{
  version_string,
  help_string
};

/* Create a symbol name to represent the sources we are annotating.
   Since there can be multiple input files, we choose the main output
   filename (stripped of any path prefixes).  Since filenames can
   contain characters that symbol names do not (eg '-') we have to
   allocate our own name.  */

static void
init_annobin_current_filename (void)
{
  char * name;
  unsigned i;

  if (annobin_current_filename != NULL
      || main_input_filename == NULL)
    return;

  name = (char *) lbasename (main_input_filename);

  if (strlen (name) == 0)
    {
      /* The name can be empty if we are receiving the source code
	 from a pipe.  In this case, we invent our own name.  */
      name = (char *) "piped_input";
    }

  if (global_file_name_symbols)
    name = strcpy ((char *) xmalloc (strlen (name) + 20), name);
  else
    name = xstrdup (name);

  /* Convert any non-symbolic characters into underscores.  */
  for (i = strlen (name); i--;)
    {
      char c = name[i];

      if (! ISALNUM (c) && c != '_' && c != '.' && c != '$')
	name[i] = '_';
      else if (i == 0 && ISDIGIT (c))
	name[i] = '_';
    }

  if (global_file_name_symbols)
    {
      /* A program can have multiple source files with the same name.
	 Or indeed the same source file can be included multiple times.
	 Or a library can be built from a sources which include file names
	 that match application file names.  Whatever the reason, we need
	 to be ensure that we generate unique global symbol names.  So we
	 append the time to the symbol name.  This will of course break
	 the functionality of build-ids.  That is why this option is off
	 by default.  */
      struct timeval tv;

      if (gettimeofday (& tv, NULL))
	{
	  annobin_inform (0, "ICE: unable to get time of day.");
	  tv.tv_sec = tv.tv_usec = 0;
	}
      sprintf (name + strlen (name),
	       "_%8.8lx_%8.8lx", (long) tv.tv_sec, (long) tv.tv_usec);
    }

  annobin_current_filename = concat (ANNOBIN_SYMBOL_PREFIX, name, NULL);
  annobin_current_endname = concat (annobin_current_filename, "_end", NULL);
}

void
annobin_inform (unsigned level, const char * format, ...)
{
  va_list args;

  if (level > 0 && level > verbose_level)
    return;

  fflush (stdout);
  fprintf (stderr, "annobin: ");
   if (main_input_filename)
     fprintf (stderr, "%s: ", main_input_filename);
  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);
  putc ('\n', stderr);
}

/* Create the assembler source necessary to build a single ELF Note structure.  */

void
annobin_output_note (const char * name,
		     unsigned     namesz,
		     bool         name_is_string,
		     const char * name_description,
		     const char * desc1,
		     const char * desc2,
		     unsigned     descsz,
		     bool         desc_is_string,
		     unsigned     type)
{
  unsigned i;

  if (asm_out_file == NULL)
    return;

  if (annobin_function_verbose && type == FUNC)
    {
      if (desc_is_string)
	annobin_inform (0, "Create function specific note for: %s: %s", desc1, name_description);
    }

  /* FIXME: When creating notes for functions we should check to see if there
     is a section name associated with that function.  If so, then we ought to
     put the notes into a sub-section named after that section.  Eg if code
     goes into .text.foo then the notes should go into .gnu.build.attributes.foo.
     Then both sections should also be placed into a section group, so that if
     the linker decides to discard .text.foo, it will also discard the notes
     as well.  (This extends to debug infomation and data as well).

     But ... at the moment, the code section is created by gcc and it is not
     associated with a section group.  We cannot add a group on afterwards and
     so we are stuck.  */
   
  if (type == OPEN || type == FUNC)
    fprintf (asm_out_file, "\t.pushsection %s\n", GNU_BUILD_ATTRS_SECTION_NAME);

  if (name == NULL)
    {
      if (namesz)
	annobin_inform (0, "ICE: null name with non-zero size");
      fprintf (asm_out_file, "\t.dc.l 0\t\t%s no name\n", ASM_COMMENT_START);
    }
  else if (name_is_string)
    {
      if (strlen ((char *) name) != namesz - 1)
	annobin_inform (0, "ICE: name string '%s' does not match name size %d", name, namesz);
      fprintf (asm_out_file, "\t.dc.l %u \t%s namesz = strlen (%s)\n", namesz, ASM_COMMENT_START, (char *) name);
    }
  else
    fprintf (asm_out_file, "\t.dc.l %u\t\t%s size of name\n", namesz, ASM_COMMENT_START);

  if (desc1 == NULL)
    {
      if (descsz)
	annobin_inform (0, "ICE: null desc1 with non-zero size");
      if (desc2 != NULL)
	annobin_inform (0, "ICE: non-null desc2 with null desc1");

      fprintf (asm_out_file, "\t.dc.l 0\t\t%s no description\n", ASM_COMMENT_START);
    }
  else if (desc_is_string)
    {
      switch (descsz)
	{
	case 0:
	  annobin_inform (0, "ICE: zero descsz with string description");
	  break;
	case 4:
	  if (annobin_is_64bit || desc2 != NULL)
	    annobin_inform (0, "ICE: descz too small");
	  if (desc1 == NULL)
	    annobin_inform (0, "ICE: descz too big");
	  break;
	case 8:
	  if (annobin_is_64bit)
	    {
	      if (desc2 != NULL)
		annobin_inform (0, "ICE: descz too small");
	    }
	  else
	    {
	      if (desc1 == NULL || desc2 == NULL)
		annobin_inform (0, "ICE: descz too big");
	    }
	  break;
	case 16:
	  if (! annobin_is_64bit || desc1 == NULL || desc2 == NULL)
	    annobin_inform (0, "ICE: descz too big");
	  break;
	default:
	  annobin_inform (0, "ICE: description string size (%d) does not match address size", descsz);
	  break;
	}

      fprintf (asm_out_file, "\t.dc.l %u%s%s descsz = sizeof (address%s)\n",
	       descsz, descsz < 10 ? "\t\t" : "\t", ASM_COMMENT_START, desc2 == NULL ? "" : "es");
    }
  else
    {
      if (desc2 != NULL)
	annobin_inform (0, "ICE: second description not empty for non-string description");

      fprintf (asm_out_file, "\t.dc.l %u\t\t%s size of description\n", descsz, ASM_COMMENT_START);
    }

  fprintf (asm_out_file, "\t.dc.l %#x\t%s type = %s\n", type, ASM_COMMENT_START,
	   type == OPEN ? "OPEN" :
	   type == FUNC ? "FUNC" :
	   type == NT_GNU_PROPERTY_TYPE_0      ? "PROPERTY_TYPE_0" : "*UNKNOWN*");

  if (name)
    {
      if (name_is_string)
	{
	  fprintf (asm_out_file, "\t.asciz \"%s\"", (char *) name);
	}
      else
	{
	  fprintf (asm_out_file, "\t.dc.b");
	  for (i = 0; i < namesz; i++)
	    fprintf (asm_out_file, " %#x%c",
		     ((unsigned char *) name)[i],
		     i < (namesz - 1) ? ',' : ' ');
	}

      fprintf (asm_out_file, "\t%s name (%s)\n",
	       ASM_COMMENT_START, name_description);

      if (namesz % 4)
	{
	  fprintf (asm_out_file, "\t.dc.b");
	  while (namesz % 4)
	    {
	      namesz++;
	      fprintf (asm_out_file, " 0%c", namesz % 4 ? ',' : ' ');
	    }
	  fprintf (asm_out_file, "\t%s Padding\n", ASM_COMMENT_START);
	}
    }

  if (desc1)
    {
      if (desc_is_string)
	{
	  if (annobin_is_64bit)
	    fprintf (asm_out_file, "\t.quad %s", (char *) desc1);
	  else
	    fprintf (asm_out_file, "\t.dc.l %s", (char *) desc1);

	  if (target_start_sym_bias)
	    {
	      /* We know that the annobin_current_filename symbol has been
		 biased in order to avoid conflicting with the function
		 name symbol for the first function in the file.  So reverse
		 that bias here.  */
	      if (desc1 == annobin_current_filename)
		fprintf (asm_out_file, "- %d", target_start_sym_bias);
	    }

	  if (desc2)
	    {
	      fprintf (asm_out_file, "\n");
	      /* FIXME: Emitting these symbol references creates a link
		 between the annobin notes section and the code section where
		 they are defined.  This prevents linker garbage collection
		 from discarding that code section, even if it is never used.
		 (It does not affact linkonce sections as they have a
		 different discard mechanism).

		 The only way to fix this is to put these notes into a
		 separate section of their own, and then to put this section
		 and the code section together into a section group.  Then
		 when the linker discards the code section it will also
		 discard the note section, and the note reloc section that the
		 assembler will create.  In order for this to work properly
		 however the linker must also arrange that if the note section
		 is not discarded, then it is inserted into the global
		 gun_build_notes section at the correct place...  */
	      if (annobin_is_64bit)
		fprintf (asm_out_file, "\t.quad %s", (char *) desc2);
	      else
		fprintf (asm_out_file, "\t.dc.l %s", (char *) desc2);
	    }

	  fprintf (asm_out_file, "\t%s description (symbol name)\n", ASM_COMMENT_START);
	}
      else
	{
	  fprintf (asm_out_file, "\t.dc.b");

	  for (i = 0; i < descsz; i++)
	    {
	      fprintf (asm_out_file, " %#x", ((unsigned char *) desc1)[i]);
	      if (i == (descsz - 1))
		fprintf (asm_out_file, "\t%s description\n", ASM_COMMENT_START);
	      else if ((i % 8) == 7)
		fprintf (asm_out_file, "\t%s description\n\t.dc.b", ASM_COMMENT_START);
	      else
		fprintf (asm_out_file, ",");
	    }

	  if (descsz % 4)
	    {
	      fprintf (asm_out_file, "\t.dc.b");
	      while (descsz % 4)
		{
		  descsz++;
		  fprintf (asm_out_file, " 0%c", descsz % 4 ? ',' : ' ');
		}
	      fprintf (asm_out_file, "\t%s Padding\n", ASM_COMMENT_START);
	    }
	}
    }

  if (type == FUNC || type == OPEN)
    fprintf (asm_out_file, "\t.popsection\n");

  fprintf (asm_out_file, "\n");
  fflush (asm_out_file);

  ++ annobin_note_count;
}

/* Fills in the DESC1, DESC2 and DESCSZ parameters for a call to annobin_output_note.  */
#define DESC_PARAMETERS(DESC1, DESC2) \
  DESC1, DESC2, (DESC1) == NULL ? 0 : (DESC2 == NULL) ? (annobin_is_64bit ? 8 : 4) : (annobin_is_64bit ? 16 : 8)

void
annobin_output_static_note (const char * buffer,
			    unsigned     buffer_len,
			    bool         name_is_string,
			    const char * name_description,
			    const char * start,
			    const char * end,
			    unsigned     note_type)
{
  annobin_output_note (buffer, buffer_len, name_is_string, name_description,
		       DESC_PARAMETERS (start, end), true, note_type);
}

void
annobin_output_bool_note (const char    bool_type,
			  const bool    bool_value,
			  const char *  name_description,
			  const char *  start,
			  const char *  end,
			  unsigned      note_type)
{
  char buffer [6];

  sprintf (buffer, "GA%c%c", bool_value ? BOOL_T : BOOL_F, bool_type);

  /* Include the NUL byte at the end of the name "string".
     This is required by the ELF spec.  */
  annobin_output_static_note (buffer, strlen (buffer) + 1, false, name_description,
			      start, end, note_type);
}

void
annobin_output_string_note (const char    string_type,
			    const char *  string,
			    const char *  name_description,
			    const char *  start,
			    const char *  end,
			    unsigned      note_type)
{
  unsigned int len = strlen (string);
  char * buffer;

  buffer = (char *) xmalloc (len + 5);

  sprintf (buffer, "GA%c%c%s", GNU_BUILD_ATTRIBUTE_TYPE_STRING, string_type, string);

  annobin_output_static_note (buffer, len + 5, true, name_description,
			      start, end, note_type);

  free (buffer);
}

void
annobin_output_numeric_note (const char     numeric_type,
			     unsigned long  value,
			     const char *   name_description,
			     const char *   start,
			     const char *   end,
			     unsigned       note_type)
{
  unsigned i;
  char buffer [32];

  sprintf (buffer, "GA%c%c", NUMERIC, numeric_type);

  if (value == 0)
    {
      /* We need to record *two* zero bytes for a zero value.  One for
	 the value itself and one as a NUL terminator, since this is a
	 name field...  */
      buffer [4] = buffer [5] = 0;
      i = 5;
    }
  else
    {
      for (i = 4; i < sizeof buffer; i++)
	{
	  buffer[i] = value & 0xff;
	  /* Note - The name field in ELF Notes must be NUL terminated, even if,
	     like here, it is not really being used as a name.  Hence the test
	     for value being zero is performed here, rather than after the shift.  */
	  if (value == 0)
	    break;
	  value >>= 8;
	}
    }

  /* If the value needs more than 8 bytes, consumers are unlikely to be able
     to handle it.  */
  if (i > 12)
    annobin_inform (0, "ICE: Numeric value for %s too big to fit into 8 bytes\n", name_description);
  if (value)
    annobin_inform (0, "ICE: Unable to record numeric value in note %s\n", name_description);

  annobin_output_static_note (buffer, i + 1, false, name_description,
			      start, end, note_type);
}

static int
compute_pic_option (void)
{
  if (flag_pie > 1)
    return 4;
  if (flag_pie)
    return 3;
  if (flag_pic > 1)
    return 2;
  if (flag_pic)
    return 1;
  return 0;
}

/* Compute a numeric value representing the settings/levels of
   the -O and -g options, and whether -Wall has been used.  This
   is to help verify the recommended hardening options for binaries.
   The format of the number is as follows:

   bits 0 -  2 : debug type (from enum debug_info_type)
   bit  3      : with GNU extensions
   bits 4 -  5 : debug level (from enum debug_info_levels)
   bits 6 -  8 : DWARF version level
   bits 9 - 10 : optimization level
   bit  11     : -Os
   bit  12     : -Ofast
   bit  13     : -Og
   bit  14     : -Wall.  */

static unsigned int
compute_GOWall_options (void)
{
  unsigned int val, i;

  /* FIXME: Keep in sync with changes to gcc/flag-types.h:enum debug_info_type.  */
  if (write_symbols > VMS_AND_DWARF2_DEBUG)
    {
      annobin_inform (0, "ICE: unknown debug info type %d\n", write_symbols);
      val = 0;
    }
  else
    val = write_symbols;

  if (use_gnu_debug_info_extensions)
    val |= (1 << 3);

  if (debug_info_level > DINFO_LEVEL_VERBOSE)
    annobin_inform (0, "ICE: unknown debug info level %d\n", debug_info_level);
  else
    val |= (debug_info_level << 4);

  if (dwarf_version < 2)
    {
      /* Apparently it is possible for dwarf_version to be -1.  Not sure how
	 this can happen, but handle it anyway.  Since DWARF prior to v2 is
	 deprecated, we use 2 as the version level.  */
      val |= (2 << 6);
      annobin_inform (1, "dwarf version level %d recorded as 2\n", dwarf_version);
    }
  else if (dwarf_version > 7)
    {
      /* FIXME: We only have 3 bits to record the debug level...  */
      val |= (7 << 6);
      annobin_inform (1, "dwarf version level %d recorded as 7\n", dwarf_version);
    }
  else
    val |= (dwarf_version << 6);

  if (optimize > 3)
    val |= (3 << 9);
  else
    val |= (optimize << 9);

  /* FIXME: It should not be possible to enable more than one of -Os/-Of/-Og,
     so the tests below could be simplified.  */
  if (optimize_size)
    val |= (1 << 11);
  if (optimize_fast)
    val |= (1 << 12);
  if (optimize_debug)
    val |= (1 << 13);

  /* Unfortunately -Wall is not recorded by gcc.  So we have to scan the
     command line...  */
  for (i = 0; i < save_decoded_options_count; i++)
    {
      if (save_decoded_options[i].opt_index == OPT_Wall)
	{
	  val |= (1 << 14);
	  break;
	}
    }

  return val;
}

static void
record_GOW_settings (unsigned int gow, bool local, const char * cname, const char * aname, const char * aname_end)
{
  char buffer [128];
  unsigned i;

  (void) sprintf (buffer, "GA%cGOW", NUMERIC);

  for (i = 7; i < sizeof buffer; i++)
    {
      buffer[i] = gow & 0xff;
      /* Note - The name field in ELF Notes must be NUL terminated, even if,
	 like here, it is not really being used as a name.  Hence the test
	 for value being zero is performed here, rather than after the shift.  */
      if (gow == 0)
	break;
      gow >>= 8;
    }

  if (local)
    {
      annobin_inform (1, "Record a change in -g/-O/-Wall status for %s", cname);
      annobin_output_note (buffer, i + 1, false, "numeric: -g/-O/-Wall",
			   DESC_PARAMETERS (aname, aname_end), true, FUNC);
    }
  else
    {
      annobin_inform (1, "Record status of -g/-O/-Wall");
      annobin_output_note (buffer, i + 1, false, "numeric: -g/-O/-Wall",
			   NULL, NULL, 0, false, OPEN);
    }
}

#ifdef flag_stack_clash_protection
static void
record_stack_clash_note (const char * start, const char * end, int type)
{
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%cstack_clash",
			  flag_stack_clash_protection ? BOOL_T : BOOL_F);

  annobin_output_static_note (buffer, len + 1, true, "bool: -fstack-clash-protection status",
			      start, end, type);
}
#endif

#ifdef flag_cf_protection
static void
record_cf_protection_note (const char * start, const char * end, int type)
{
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%ccf_protection", NUMERIC);

  /* We bias the flag_cf_protection enum value by 1 so that we do not get confused by a zero value.  */
  buffer[++len] = flag_cf_protection + 1;
  buffer[++len] = 0;

  annobin_inform (1, "Record cf-protection status of %d", flag_cf_protection);
  annobin_output_static_note (buffer, len + 1, false, "numeric: -fcf-protection status",
			      start, end, type);
}
#endif

static const char *
function_asm_name (void)
{
  if (! current_function_decl)
    return NULL;

  tree name = DECL_ASSEMBLER_NAME (current_function_decl);

  if (name == NULL)
    return NULL;

  const char * id = IDENTIFIER_POINTER (name);

  if (id == NULL)
    return NULL;

  /* Functions annotated with the asm() function attribute will have
     an asterisk prefix.  Skip it, so that we do not generate invalid
     assembler symbol names.  */
  if (*id == '*')
    id ++;

  if (*id == '0')
    return NULL;

  return id;
}

static const char * saved_end_sym;

static void
annobin_emit_function_notes (const char *  func_name,
			     const char *  start_sym,
			     const char *  end_sym,
			     bool          force)
{
  unsigned int count = annobin_note_count;

  if (force)
    {
      /* XXX FIXME - generate the other global style notes as well.  */
    }

  annobin_target_specific_function_notes (start_sym, end_sym, force);
  /* If one or more notes were generated by the target specific function
     then we no longer need to include the start/end symbols in any
     futher notes that we gebenerate.  */
  if (annobin_note_count > count)
    start_sym = end_sym = NULL;

  if (flag_stack_protect != -1
      && (force
	  || global_stack_prot_option != flag_stack_protect))
    {
      annobin_inform (1, "Recording stack protection status of %d for %s",
		      flag_stack_protect, func_name); 

      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_STACK_PROT, flag_stack_protect,
				   "numeric: -fstack-protector status",
				   start_sym, end_sym, FUNC);

      /* We no longer need to include the symbols in the notes we generate.  */
      start_sym = end_sym = NULL;
    }

#ifdef flag_stack_clash_protection
  if (force
      || global_stack_clash_option != flag_stack_clash_protection)
    {
      annobin_inform (1, "Recording stack clash protection status of %d for %s",
		      flag_stack_clash_protection, func_name);

      record_stack_clash_note (start_sym, end_sym, FUNC);
      start_sym = end_sym = NULL;
    }
#endif

#ifdef flag_cf_protection
  if (force
      || global_cf_option != flag_cf_protection)
    {
      annobin_inform (1, "Recording control flow protection status of %d for %s",
		      flag_cf_protection, func_name);

      record_cf_protection_note (start_sym, end_sym, FUNC);
      start_sym = end_sym = NULL;
    }
#endif

  if (force
      || global_pic_option != compute_pic_option ())
    {
      annobin_inform (1, "Recording PIC status of %s", func_name);
      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_PIC, compute_pic_option (),
				   "numeric: pic type", start_sym, end_sym,
				   FUNC);
      start_sym = end_sym = NULL;
    }

  if (force
      || global_GOWall_options != compute_GOWall_options ())
    {
      record_GOW_settings (compute_GOWall_options (), true, func_name, start_sym, end_sym);

      start_sym = end_sym = NULL;
    }

  if (flag_short_enums != -1
      && (force
	  || global_short_enums != flag_short_enums))
    {
      annobin_inform (1, "Recording enum size for %s", func_name);
      annobin_output_bool_note (GNU_BUILD_ATTRIBUTE_SHORT_ENUM, flag_short_enums,
				flag_short_enums ? "bool: short-enums: on" : "bool: short-enums: off",
				start_sym, end_sym, FUNC);
      start_sym = end_sym = NULL;
    }

  if (annobin_enable_stack_size_notes && flag_stack_usage_info)
    {
      if ((unsigned long) current_function_static_stack_size > stack_threshold)
	{
	  annobin_inform (1, "Recording stack usage of %lu for %s",
			  current_function_static_stack_size, func_name);

	  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_STACK_SIZE,
				       current_function_static_stack_size,
				       "numeric: stack-size",
				       start_sym, end_sym, FUNC);
	  start_sym = end_sym = NULL;
	}

      annobin_total_static_stack_usage += current_function_static_stack_size;

      if ((unsigned long) current_function_static_stack_size > annobin_max_stack_size)
	annobin_max_stack_size = current_function_static_stack_size;
    }
}

#if 0
/* These includes are needed in order to be able to access crtl->  */
#include "rtl.h"
#include "memmodel.h"
#include "emit-rtl.h"
#endif

/* Create any notes specific to the current function.  */

static void
annobin_create_function_notes (void * gcc_data, void * user_data)
{
  const char * func_section;
  const char * func_name;
  const char * asm_name;
  const char * start_sym;
  const char * end_sym;
  bool         force;
  unsigned int count;

  if (saved_end_sym != NULL)
    annobin_inform (0, "XXX ICE: end sym %s not NULL\n", saved_end_sym);

  if (! annobin_enable_static_notes || asm_out_file == NULL)
    return;

  func_section = DECL_SECTION_NAME (current_function_decl);
#if 0 /* We cannot call function_section() - this might create
	 a NEW section which could be incompatible with the section
	 that will ultimately be created for this function.  See:
	   https://bugzilla.redhat.com/show_bug.cgi?id=1598961
	 for an example of this.  */
  if (func_section == NULL)
    {
      section * sec = function_section (current_function_decl);

      if (sec != NULL)
	{
	  if (sec->common.flags & SECTION_NAMED)
	    func_section = sec->named.name;
	}
    }
#endif

  func_name = current_function_name ();
  asm_name  = function_asm_name ();

  if (func_name == NULL)
    {
      func_name = asm_name;

      if (func_name == NULL)
	{
	  /* Can this happen ?  */
	  annobin_inform (0, "ICE: function name not available");
	  return;
	}
    }

  if (asm_name == NULL)
    asm_name = func_name;

  if (func_section == NULL && flag_function_sections)
    func_section = concat (".text.", asm_name, NULL); /* FIXME: memory leak.  */
  
  /* If the function is going to be in its own section, then we do not know
     where it will end up in memory.  In particular we cannot rely upon it
     being included in the memory range covered by the global notes.  So for
     such functions we always generate a full range of notes.
     Likewise if the compiler is generating cold code, then we need to emit
     notes for the cold section as well.  */
  force = func_section != NULL;

  /* We use our own function start and end symbols so that they will
     not interfere with the program proper.  In particular if we use
     the function name symbol ourselves then we can cause problems
     when the linker attempts to relocs against it and finds that it
     has both PC relative and abolsute relocs.
     
     We try our best to ensure that the new symbols will not clash
     with any other symbols in the program.  */
  start_sym = concat (ANNOBIN_SYMBOL_PREFIX, asm_name, ".start", NULL);
  end_sym = concat (ANNOBIN_SYMBOL_PREFIX, asm_name, ".end", NULL);

  count = annobin_note_count;
  annobin_emit_function_notes (func_name, start_sym, end_sym, force);
  
  if (annobin_note_count > count)
    {
      /* If we generated any notes then we must make sure that the start
	 symbol has been emitted as well.  The end symbols will be emitted
	 by annobin_create_function_end_symbol, once the body of the function
	 has been written to the assembler file.

	 Note we cannot just use ".equiv start_sym, asm_name", as the
	 assembler symbol might have a special type, eg ifunc, and this
	 would be inherited by our symbol.  */
      if (func_section == NULL)
	{
	  fprintf (asm_out_file, "\t.type %s, STT_NOTYPE\n", start_sym);
	  fprintf (asm_out_file, "\t.hidden %s\n", start_sym);
	  fprintf (asm_out_file, "%s:\n", start_sym);
	}
      else
	{
	  fprintf (asm_out_file, "\t.pushsection %s, \"ax\"\n", func_section);
	  fprintf (asm_out_file, "\t.type %s, STT_NOTYPE\n", start_sym);
	  fprintf (asm_out_file, "\t.hidden %s\n", start_sym);
	  fprintf (asm_out_file, "%s:\n", start_sym);
	  fprintf (asm_out_file, "\t.popsection\n");

	  /* If the function is in a linkonce section then it is possible that
	     it will be removed by the linker.  In that case we could be left
	     with a dangling reference from the annobin notes to the now
	     deleted annobin symbols in the function section.  So we provide
	     weak definitions of the symbols here.  We also make them
	     hidden in order to indicate that they are not needed elsewhere.

	     Note that linker garbage collection does not trigger this problem
	     because the references generated by the notes prevent garbage
	     collection from working.  The only way around this is to use
	     section groups, but - FIXME - this needs more work.  See the
	     comment in annobin_output_note() for more details.

	     FIXME - Do we need to worry about COMDAT code sections ?  */
	  if (strstr (func_section, ".gnu.linkonce."))
	    {
	      fprintf (asm_out_file, "\t.pushsection %s\n", GNU_BUILD_ATTRS_SECTION_NAME);
	      fprintf (asm_out_file, "\t.weak %s\n", start_sym);
	      fprintf (asm_out_file, "\t.hidden %s\n", start_sym);
	      fprintf (asm_out_file, "\t.weak %s\n", end_sym);
	      fprintf (asm_out_file, "\t.hidden %s\n", end_sym);
	      fprintf (asm_out_file, "\t.popsection\n");
	    }
	}

      saved_end_sym = end_sym;
    }
  else
    {
      free ((void *) end_sym);
    }

  free ((void *) start_sym);
#if 0
  annobin_inform (0, "START: bb %d label %p", crtl->has_bb_partition, crtl->subsections.cold_section_label);
#endif
}


static void
annobin_create_function_end_symbol (void * gcc_data, void * user_data)
{
  if (! annobin_enable_static_notes || asm_out_file == NULL)
    return;

#if 0
  annobin_inform (0, "END: bb %d label %p", crtl->has_bb_partition, crtl->subsections.cold_section_label);
#endif
  if (saved_end_sym)
    {
      const char * dsn = DECL_SECTION_NAME (current_function_decl);

      if (dsn)
	{
	  /* The push/pop are probably not necessary, but let's be paranoid.  */
	  fprintf (asm_out_file, "\t.pushsection %s\n", dsn);
	  fprintf (asm_out_file, "\t.hidden %s\n", saved_end_sym);
	  fprintf (asm_out_file, "%s:\n", saved_end_sym);
	  fprintf (asm_out_file, "\t.popsection\n");
	}
      else
	{
	  fprintf (asm_out_file, "\t.hidden %s\n", saved_end_sym);
	  fprintf (asm_out_file, "%s:\n", saved_end_sym);
	}

      free ((void *) saved_end_sym);
      saved_end_sym = NULL;
    }
#if 0
  switch_to_section (unlikely_text_section ());
  fprintf (asm_out_file, ".xxx\n");
  
  /* Determine if this function has a cold section.
     Note - we cannot use gcc's cold_function_name variable as this
     is not kept in sync with the current function.  */
  
  if (crtl->has_bb_partition)
    {
      /* If the function has a cold portion it will be emitted into a
	 separate section.  So we must create a whole set of notes for
	 them too.  */

      const char * cold_name = current_function_name ();
      const char * cold_start_sym;
      const char * cold_end_sym;

      annobin_inform (0, "func sec cold name %s\n", cold_name);
      
      cold_start_sym = concat (ANNOBIN_SYMBOL_PREFIX, ".cold.", cold_name, ".start", NULL);
      cold_end_sym = concat (ANNOBIN_SYMBOL_PREFIX, ".cold.", cold_name, ".end", NULL);
      
      switch_to_section (unlikely_text_section ());
      fprintf (asm_out_file, "\t.hidden %s\n", cold_start_sym);
      fprintf (asm_out_file, "\t.equiv %s, %s\n", cold_start_sym, cold_name);
      fprintf (asm_out_file, "\t.hidden %s\n", cold_end_sym);
      fprintf (asm_out_file, "%s:\n", cold_end_sym);

      annobin_emit_function_notes (cold_name, cold_start_sym, cold_end_sym, true);

      free ((void *) cold_start_sym);
      free ((void *) cold_end_sym);
    }
#endif
}

static void
record_fortify_level (int level)
{
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%cFORTIFY", NUMERIC);

  buffer[++len] = level;
  buffer[++len] = 0;
  annobin_output_note (buffer, len + 1, false, "FORTIFY SOURCE level",
		       NULL, NULL, 0, false, OPEN);
  annobin_inform (1, "Record a FORTIFY SOURCE level of %d", level);
}

static void
record_glibcxx_assertions (bool on)
{
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%cGLIBCXX_ASSERTIONS", on ? BOOL_T : BOOL_F);

  annobin_output_note (buffer, len + 1, false, on ? "_GLIBCXX_ASSERTIONS defined" : "_GLIBCXX_ASSERTIONS not defined",
		       NULL, NULL, 0, false, OPEN);
  annobin_inform (1, "Record a _GLIBCXX_ASSERTIONS as %s", on ? "defined" : "not defined");
}

static void
annobin_create_global_notes (void * gcc_data, void * user_data)
{
  int i;
  char buffer [1024]; /* FIXME: Is this enough ?  */

  if (! annobin_enable_static_notes)
    return;

  if (asm_out_file == NULL)
    {
      /* This happens during LTO compilation.  Compilation is triggered
	 before any output file has been opened.  Since we do not have
	 the file handle we cannot emit any notes.  On the other hand,
	 the recompilation process will repeat later on with a real
	 output file and so the notes can be generated then.  */
      annobin_inform (1, "Output file not available - unable to generate notes");
      return;
    }

  /* Record global information.
     Note - we do this here, rather than in plugin_init() as some
     information, PIC status or POINTER_SIZE, may not be initialised
     until after the target backend has had a chance to process its
     command line options, and this happens *after* plugin_init.  */

  /* Compute the default data size.  */
  switch (POINTER_SIZE)
    {
    case 16:
    case 32:
      annobin_is_64bit = false; break;
    case 64:
      annobin_is_64bit = true; break;
    default:
      annobin_inform (0, _("Unknown target pointer size: %d"), POINTER_SIZE);
    }

  if (annobin_enable_stack_size_notes)
    /* We must set this flag in order to obtain per-function stack usage info.  */
    flag_stack_usage_info = 1;

#ifdef flag_stack_clash_protection
  global_stack_clash_option = flag_stack_clash_protection;
#endif
#ifdef flag_cf_protection
  global_cf_option = flag_cf_protection;
#endif
  global_stack_prot_option = flag_stack_protect;
  global_pic_option = compute_pic_option ();
  global_short_enums = flag_short_enums;
  global_GOWall_options = compute_GOWall_options ();

  /* Output a file name symbol to be referenced by the notes...  */
  if (annobin_current_filename == NULL)
    init_annobin_current_filename ();
  if (annobin_current_filename == NULL)
    {
      annobin_inform (0, "ICE: Could not find output filename");
      /* We need a filename, so invent one.  */
      annobin_current_filename = (char *) "unknown_source";
    }

  /* It is possible that no code will end up in the .text section.
     Eg because the compilation was run with the -ffunction-sections option.
     Nevertheless we generate this symbol in the .text section
     as at this point we cannot know which section(s) will be used
     by compiled code.  */
  fprintf (asm_out_file, "\t.pushsection .text\n");

  /* Create a symbol for this compilation unit.  */
  if (global_file_name_symbols)
    fprintf (asm_out_file, "\t.global %s\n", annobin_current_filename);
  else
    fprintf (asm_out_file, "\t.hidden %s\n", annobin_current_filename);

  /* Note - we used to set the type of the symbol to STT_OBJECT, but that is
     incorrect because that type is for:
       "A data object, such as a variable, an array, and so on".

     There is no ELF symbol to represent a compilation unit, (STT_FILE only
     covers a single source file and has special sematic requirements), so
     instead we use STT_NOTYPE.  (Ideally we could use STT_LOOS+n, but there
     is a problem with the GAS assembler, which does not allow such values to
     be set on symbols).  */
  fprintf (asm_out_file, "\t.type %s, STT_NOTYPE\n", annobin_current_filename);

  if (target_start_sym_bias)
    {
      /* We set the address of the start symbol to be the current address plus
	 a bias value.  That way this symbol will not be confused for a file
	 start/function start symbol.

	 There is special code in annobin_output_note() that undoes this bias
	 when the symbol's address is being used to compute a range for the
	 notes.  */
      fprintf (asm_out_file, "\t.equiv %s, . + %d\n", annobin_current_filename,
	       target_start_sym_bias);
    }
  else
      fprintf (asm_out_file, "\t.equiv %s, .\n", annobin_current_filename);

  /* We explicitly set the size of the symbol to 0 so that it will not
     confuse other tools (eg GDB, elfutils) which look for symbols that
     cover an address range.  */
  fprintf (asm_out_file, "\t.size %s, 0\n", annobin_current_filename);

  fprintf (asm_out_file, "\t.popsection\n");

  /* Create the static notes section.  */
#if 0
  /* The SHF_GNU_BUILD_NOTE section flag has not been officially accepted yet.  */
  fprintf (asm_out_file, "\t.pushsection %s, \"%#x\", %%note\n",
	   GNU_BUILD_ATTRS_SECTION_NAME, SHF_GNU_BUILD_NOTE);
#else
  fprintf (asm_out_file, "\t.pushsection %s, \"\", %%note\n",
	   GNU_BUILD_ATTRS_SECTION_NAME);
#endif
  fprintf (asm_out_file, "\t.balign 4\n");

  /* Output the version of the specification supported.  */
  sprintf (buffer, "%dp%d", SPEC_VERSION, annobin_version);
  annobin_output_string_note (GNU_BUILD_ATTRIBUTE_VERSION, buffer,
			      "string: version",
			      annobin_current_filename,
			      annobin_current_endname,
			      OPEN);

  /* Record the version of the compiler.  */
  annobin_output_string_note (GNU_BUILD_ATTRIBUTE_TOOL, compiler_version,
			      "string: build-tool", NULL, NULL, OPEN);

  /* Record optimization level, -W setting and -g setting  */
  record_GOW_settings (global_GOWall_options, false, NULL, NULL, NULL);

  /* Record -fstack-protector option.  */
  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_STACK_PROT,
			       /* See BZ 1563141 for an example where global_stack_protection can be -1.  */
			       global_stack_prot_option >=0 ? global_stack_prot_option : 0,
			       "numeric: -fstack-protector status",
			       NULL, NULL, OPEN);

#ifdef flag_stack_clash_protection
  /* Record -fstack-clash-protection option.  */
  record_stack_clash_note (NULL, NULL, OPEN);
#endif
#ifdef flag_cf_protection
  /* Record -fcf-protection option.  */
  record_cf_protection_note (NULL, NULL, OPEN);
#endif

  /* Look for -D _FORTIFY_SOURCE=<n> and -D_GLIBCXX_ASSERTIONS on the
     original gcc command line.  Scan backwards so that we record the
     last version of the option, should multiple versions be set.  */
  bool fortify_level_recorded = false;
  bool glibcxx_assertions_recorded = false;

  for (i = save_decoded_options_count; i--;)
    {
      if (save_decoded_options[i].opt_index == OPT_D)
	{
	  if (save_decoded_options[i].arg == NULL)
	    continue;

	  annobin_inform (2, "decoded arg %s", save_decoded_options[i].arg);

	  if (strncmp (save_decoded_options[i].arg, "_FORTIFY_SOURCE=", strlen ("_FORTIFY_SOURCE=")) == 0)
	    {
	      int level = atoi (save_decoded_options[i].arg + strlen ("_FORTIFY_SOURCE="));

	      if (level < 0 || level > 3)
		{
		  annobin_inform (0, "Unexpected value for FORIFY SOURCE: %s",
				  save_decoded_options[i].arg);
		  level = 0;
		}

	      if (! fortify_level_recorded)
		{
		  record_fortify_level (level);
		  fortify_level_recorded = true;
		}

	      continue;
	    }

	  if (strncmp (save_decoded_options[i].arg, "_GLIBCXX_ASSERTIONS", strlen ("_GLIBCXX_ASSERTIONS")) == 0)
	    {
	      if (! glibcxx_assertions_recorded)
		{
		  record_glibcxx_assertions (true);
		  glibcxx_assertions_recorded = true;
		}

	      continue;
	    }
	}
      else if (save_decoded_options[i].opt_index == OPT_fpreprocessed)
	{
	  /* Preprocessed sources *might* have had -D_FORTIFY_SOURCE=<n>
	     applied, but we cannot tell from here.  Well not without a
	     deep inspection of the preprocessed sources.  So instead we
	     record a level of -1 to let the user known that we do not know.
	     Note: preprocessed sources includes the use of --save-temps.  */
	  record_fortify_level (-1);
	  fortify_level_recorded = true;
	  record_glibcxx_assertions (false); /* FIXME: need a tri-state value...  */
	  glibcxx_assertions_recorded = true;
	  break;
	}
    }

  if (! fortify_level_recorded)
    record_fortify_level (0);

  if (! glibcxx_assertions_recorded)
    record_glibcxx_assertions (false);

  /* Record the PIC status.  */
  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_PIC, global_pic_option,
			       "numeric: PIC", NULL, NULL, OPEN);

  /* Record enum size.  */
  annobin_output_bool_note (GNU_BUILD_ATTRIBUTE_SHORT_ENUM, global_short_enums != 0,
			    global_short_enums != 0 ? "bool: short-enums: on" : "bool: short-enums: off",
			    NULL, NULL, OPEN);

  /* Record target specific notes.  */
  annobin_record_global_target_notes ();

  fprintf (asm_out_file, "\t.popsection\n");
  fflush (asm_out_file);
}

static void
annobin_create_loader_notes (void * gcc_data, void * user_data)
{
  if (asm_out_file == NULL)
    return;

  /* It is possible that there is no code in the .text section.
     Eg because the compilation was run with the -ffunction-sections option.
     Nevertheless we generate this symbol because it is needed by the
     version note that was generated in annobin_create_global_notes().  */
  fprintf (asm_out_file, "\t.pushsection .text\n");
  if (global_file_name_symbols)
    fprintf (asm_out_file, "\t.global %s\n", annobin_current_endname);
  else
    fprintf (asm_out_file, "\t.hidden %s\n", annobin_current_endname);
  fprintf (asm_out_file, "%s:\n", annobin_current_endname);
  fprintf (asm_out_file, "\t.type %s, STT_NOTYPE\n", annobin_current_endname);
  fprintf (asm_out_file, "\t.size %s, 0\n", annobin_current_endname);
  fprintf (asm_out_file, "\t.popsection\n");

  if (! annobin_enable_dynamic_notes)
    return;

  if (annobin_enable_stack_size_notes && annobin_total_static_stack_usage)
    {
      annobin_inform (1, "Recording total static usage of %ld", annobin_total_static_stack_usage);

      fprintf (asm_out_file, "\t.pushsection %s\n", GNU_BUILD_ATTRS_SECTION_NAME);
      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_STACK_SIZE, annobin_total_static_stack_usage,
				   "numeric: stack-size", NULL, NULL, OPEN);
      fprintf (asm_out_file, "\t.popsection\n");
    }

  annobin_target_specific_loader_notes ();
}

static bool
parse_args (unsigned argc, struct plugin_argument * argv)
{
  while (argc--)
    {
      char * key = argv[argc].key;

      while (*key == '-')
	++ key;

      /* These options allow the plugin to be enabled/disabled by a build
	 system without having to change the option that loads the plugin
	 itself.  */
      if (strcmp (key, "disable") == 0)
	enabled = false;

      else if (strcmp (key, "enable") == 0)
	enabled = true;

      else if (strcmp (key, "help") == 0)
	annobin_inform (0, help_string);

      else if (strcmp (key, "version") == 0)
	annobin_inform (0, version_string);

      else if (strcmp (key, "verbose") == 0)
	verbose_level ++;

      else if (strcmp (key, "function-verbose") == 0)
	annobin_function_verbose = true;

      else if (strcmp (key, "global-file-syms") == 0)
	global_file_name_symbols = true;
      else if (strcmp (key, "no-global-file-syms") == 0)
	global_file_name_symbols = false;

      else if (strcmp (key, "stack-size-notes") == 0)
	annobin_enable_stack_size_notes = true;
      else if (strcmp (key, "no-stack-size-notes") == 0)
	annobin_enable_stack_size_notes = false;

      else if (strcmp (key, "dynamic-notes") == 0)
	annobin_enable_dynamic_notes = true;
      else if (strcmp (key, "no-dynamic-notes") == 0)
	annobin_enable_dynamic_notes = false;

      else if (strcmp (key, "static-notes") == 0)
	annobin_enable_static_notes = true;
      else if (strcmp (key, "no-static-notes") == 0)
	annobin_enable_static_notes = false;

      else if (strcmp (key, "stack-threshold") == 0)
	{
	  stack_threshold = strtoul (argv[argc].value, NULL, 0);
	  if (stack_threshold == 0)
	    stack_threshold = DEFAULT_THRESHOLD;
	}

      else
	{
	  annobin_inform (0, "unrecognised option: %s", argv[argc].key);
	  return false;
	}
    }

  return true;
}

int
plugin_init (struct plugin_name_args *   plugin_info,
             struct plugin_gcc_version * version)
{
  if (!plugin_default_version_check (version, & gcc_version))
    {
      bool fail = false;

      if (strcmp (version->basever, gcc_version.basever))
	{
	  annobin_inform (0, _("Error: plugin built for compiler version (%s) but run with compiler version (%s)"),
			  gcc_version.basever, version->basever);
	  fail = true;
	}

      /* Since the plugin is not part of the gcc project, it is entirely
	 likely that it has been built on a different day.  This is not
	 a showstopper however, since compatibility will be retained as
	 long as the correct headers were used.  */
      if (strcmp (version->datestamp, gcc_version.datestamp))
	annobin_inform (1, _("Plugin datestamp (%s) is different from compiler datestamp (%s)"),
			version->datestamp, gcc_version.datestamp);

      /* Unlikely, but also not serious.  */
      if (strcmp (version->devphase, gcc_version.devphase))
	annobin_inform (1, _("Plugin built for compiler development phase (%s) not (%s)"),
		     version->devphase, gcc_version.devphase);

      /* Theoretically this could be a problem, in practice it probably isn't.  */
      if (strcmp (version->revision, gcc_version.revision))
	annobin_inform (1, _("Warning: plugin built for compiler revision (%s) not (%s)"),
		     version->revision, gcc_version.revision);

      if (strcmp (version->configuration_arguments, gcc_version.configuration_arguments))
	{
	  const char * plugin_target;
	  const char * gcc_target;
	  const char * plugin_target_end;
	  const char * gcc_target_end;

	  /* The entire configuration string can be very verbose,
	     so try to catch the case of compiler and plugin being
	     built for different targets and tell the user just that.  */
	  plugin_target = strstr (version->configuration_arguments, "target=");
	  gcc_target = strstr (gcc_version.configuration_arguments, "target=");
	  if (plugin_target)
	    {
	      plugin_target += 7; /* strlen ("target=") */
	      plugin_target_end = strchr (plugin_target, ' ');
	    }
	  else
	    {
	      plugin_target = "native";
	      plugin_target_end = gcc_target + 6; /* strlen ("native")  */
	    }
	  if (gcc_target)
	    {
	      gcc_target += 7;
	      gcc_target_end = strchr (gcc_target, ' ');
	    }
	  else
	    {
	      gcc_target = "native";
	      gcc_target_end = gcc_target + 6;
	    }

	  if (plugin_target_end
	      && gcc_target_end
	      && strncmp (plugin_target, gcc_target, plugin_target_end - plugin_target))
	    {
	      annobin_inform (0, _("Error: plugin run on a %.*s compiler but built on a %.*s compiler"),
			   plugin_target_end - plugin_target, plugin_target,
			   gcc_target_end - gcc_target, gcc_target);
	      fail = true;
	    }
	  else
	    {
	      annobin_inform (1, _("Plugin run on a compiler configured as (%s) not (%s)"),
			   version->configuration_arguments, gcc_version.configuration_arguments);
	    }
	}

      if (fail)
	return 1;
    }

  if (! parse_args (plugin_info->argc, plugin_info->argv))
    {
      annobin_inform (1, _("failed to parse arguments to the plugin"));
      return 1;
    }

  if (! enabled)
    return 0;

  if (! annobin_enable_dynamic_notes && ! annobin_enable_static_notes)
    {
      annobin_inform (1, _("nothing to be done"));
      return 0;
    }

  /* Record global compiler options.  */
  compiler_version = (char *) xmalloc (strlen (version->basever) + strlen (version->datestamp) + 6);
  sprintf (compiler_version, "gcc %s %s", version->basever, version->datestamp);

  annobin_save_target_specific_information ();

  target_start_sym_bias = annobin_target_start_symbol_bias ();

  register_callback (plugin_info->base_name,
		     PLUGIN_INFO,
		     NULL,
		     & annobin_info);

  register_callback ("annobin: Generate global annotations",
		     PLUGIN_START_UNIT,
		     annobin_create_global_notes,
		     NULL);

  register_callback ("annobin: Generate per-function annotations",
		     PLUGIN_ALL_PASSES_START,
		     annobin_create_function_notes,
		     NULL);

  register_callback ("annobin: Register per-function end symbol",
		     PLUGIN_ALL_PASSES_END,
		     annobin_create_function_end_symbol,
		     NULL);

  register_callback ("annobin: Generate final annotations",
		     PLUGIN_FINISH_UNIT,
		     annobin_create_loader_notes,
		     NULL);
  return 0;
}
