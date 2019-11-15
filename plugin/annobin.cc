/* annobin - a gcc plugin for annotating binary files.
   Copyright (c) 2017 - 2019 Red Hat.
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

/* Needed to access some of GCC's internal structures.  */
#include "cgraph.h"
#include "target.h"
#if GCCPLUGIN_VERSION_MAJOR >= 5
#include "errors.h"
#else
#include "diagnostic-core.h"
#endif

/* Version number.  NB: Keep the numeric and string versions in sync
   Also, keep in sync with the major_version and minor_version definitions
   in annocheck/annocheck.c.
   FIXME: This value should be defined in only one place...  */
static unsigned int   annobin_version = 890;
static const char *   version_string = N_("Version 890");

/* Prefix used to isolate annobin symbols from program symbols.  */
#define ANNOBIN_SYMBOL_PREFIX ".annobin_"

/* Suffix used to turn a section name into a group name.  */
#define ANNOBIN_GROUP_NAME    ".group"

/* Section names (and section name prefixes) used by gcc.  */
#define CODE_SECTION     ".text"
#define HOT_SUFFIX       ".hot"
#define HOT_SECTION      CODE_SECTION HOT_SUFFIX
#define COLD_SUFFIX      ".unlikely"
#define COLD_SECTION     CODE_SECTION COLD_SUFFIX
#define STARTUP_SUFFIX   ".startup"
#define STARTUP_SECTION  CODE_SECTION STARTUP_SUFFIX
#define EXIT_SUFFIX      ".exit"
#define EXIT_SECTION     CODE_SECTION EXIT_SUFFIX

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

static const char *   plugin_name = NULL;

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

/* True if annobin should generate gcc errors if gcc command line options are wrong.  */
static bool           annobin_active_checks = false;

#ifdef flag_stack_clash_protection
static int            global_stack_clash_option = -1;
#endif
#ifdef flag_cf_protection
static int            global_cf_option = -1;
#endif
static bool           global_omit_frame_pointer;
static bool           annobin_enable_attach = true;
static signed int     target_start_sym_bias = 0;
static unsigned int   annobin_note_count = 0;
static unsigned int   global_GOWall_options = 0;
static int            global_stack_prot_option = 0;
static int            global_pic_option = 0;
static int            global_short_enums = 0;
static int            global_fortify_level = -1;
static int            global_glibcxx_assertions = -1;
static char *         build_version = NULL;
static char *         run_version = NULL;
static unsigned       verbose_level = 0;
#define BE_VERBOSE   (verbose_level > 0)
static const char *   annobin_extra_prefix = "";
static char *         annobin_current_filename = NULL;
static char *         annobin_current_endname  = NULL;
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
   [no-]attach            Do [do not] attempt to attach function sections to group sections\n\
   [no-]active-checks     Do [do not] generate errors if gcc command line options are wrong.  (Default: do not)\n\
   rename                 Add a prefix to the filename symbols so that two annobin plugins can be active at the same time\n \
   stack-threshold=N      Only create function specific stack size notes when the size is > N.");

static struct plugin_info annobin_info =
{
  version_string,
  help_string
};

void
annobin_inform (unsigned level, const char * format, ...)
{
  va_list args;

  if (level > 0 && level > verbose_level)
    return;

  fflush (stdout);

  if (plugin_name)
    fprintf (stderr, "%s: ", plugin_name);
  else
    fprintf (stderr, "annobin: ");
    
  if (main_input_filename)
    fprintf (stderr, "%s: ", main_input_filename);

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  putc ('\n', stderr);
}

void
ice (const char * text)
{
  annobin_inform (INFORM_ALWAYS, "ICE: %s", text);
  annobin_inform (INFORM_ALWAYS, "ICE: Please contact the annobin maintainer with details of this problem");
}

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
	  ice ("unable to get time of day.");
	  tv.tv_sec = tv.tv_usec = 0;
	}
      sprintf (name + strlen (name),
	       "_%8.8lx_%8.8lx", (long) tv.tv_sec, (long) tv.tv_usec);
    }

  annobin_current_filename = concat (ANNOBIN_SYMBOL_PREFIX, annobin_extra_prefix, name, NULL);
  annobin_current_endname = concat (annobin_current_filename, "_end", NULL);
}

static void
annobin_emit_asm (const char * text, const char * comment)
{
  unsigned len = 0;

  if (text)
    {
      fprintf (asm_out_file, "\t");
      len = fprintf (asm_out_file, "%s", text);
    }
  if (flag_verbose_asm && comment)
    {
      if (len == 0)
	;
      if (len < 8)
	fprintf (asm_out_file, "\t\t");
      else
	fprintf (asm_out_file, "\t");

      fprintf (asm_out_file, "%s %s", ASM_COMMENT_START, comment);
    }

  fprintf (asm_out_file, "\n");
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
		     unsigned     type,
		     const char * sec_name)
{
  char buffer1[24];
  char buffer2[128];
  unsigned i;

  if (asm_out_file == NULL)
    return;

  if (annobin_function_verbose && type == FUNC)
    {
      if (desc_is_string)
	annobin_inform (INFORM_ALWAYS, "Create function specific note for: %s: %s", desc1, name_description);
    }

  if (strchr (sec_name, ','))
    fprintf (asm_out_file, "\t.pushsection %s\n", sec_name);
  else
    fprintf (asm_out_file, "\t.pushsection %s, \"\", %%note\n", sec_name);

  /* Note we use 4-byte alignment even on 64-bit targets.  This might seem
     wrong for 64-bit systems, but the ELF standard does not specify any
     alignment requirements for notes, and it matches already established
     practice for other types of notes.  Plus it helps reduce the size of
     the notes on 64-bit systems which is a good thing.  */
  fprintf (asm_out_file, "\t.balign 4\n");

  if (name == NULL)
    {
      if (namesz)
	ice ("null name with non-zero size");

      annobin_emit_asm (".dc.l 0", "no name");
    }
  else if (name_is_string)
    {
      if (strlen ((char *) name) != namesz - 1)
	ice ("name string does not match name size");

      sprintf (buffer1, ".dc.l %u", namesz);
      sprintf (buffer2 , "namesz [= strlen (%s)]", name);
      annobin_emit_asm (buffer1, buffer2);
    }
  else
    {
      sprintf (buffer1, ".dc.l %u", namesz);
      annobin_emit_asm (buffer1, "size of name");
    }

  if (desc1 == NULL)
    {
      if (descsz)
	ice ("null desc1 with non-zero size");
      if (desc2 != NULL)
	ice ("non-null desc2 with null desc1");

      annobin_emit_asm (".dc.l 0", "no description");
    }
  else if (desc_is_string)
    {
      switch (descsz)
	{
	case 0:
	  ice ("zero descsz with string description");
	  break;
	case 4:
	  if (annobin_is_64bit || desc2 != NULL)
	    ice ("descz too small");
	  if (desc1 == NULL)
	    ice ("descz too big");
	  break;
	case 8:
	  if (annobin_is_64bit)
	    {
	      if (desc2 != NULL)
		ice ("descz too small");
	    }
	  else
	    {
	      if (desc1 == NULL || desc2 == NULL)
		ice ("descz too big");
	    }
	  break;
	case 16:
	  if (! annobin_is_64bit || desc1 == NULL || desc2 == NULL)
	    ice ("descz too big");
	  break;
	default:
	  ice ("description string size does not match address size");
	  break;
	}

      sprintf (buffer1, ".dc.l %u", descsz);
      annobin_emit_asm (buffer1, desc2 == NULL ? "descsz [= sizeof (address)]" : "descsz [= 2 * sizeof (address)]");
    }
  else
    {
      if (desc2 != NULL)
	ice ("second description not empty for non-string description");

      sprintf (buffer1, ".dc.l %u", descsz);
      annobin_emit_asm (buffer1, "size of description");
    }

  sprintf (buffer1, ".dc.l %#x", type);
  annobin_emit_asm (buffer1,
		    type == OPEN ? "OPEN" :
		    type == FUNC ? "FUNC" :
		    type == NT_GNU_PROPERTY_TYPE_0 ? "PROPERTY_TYPE_0" : "*UNKNOWN*");

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

      annobin_emit_asm (NULL, name_description);

      if (namesz % 4)
	{
	  fprintf (asm_out_file, "\t.dc.b");
	  while (namesz % 4)
	    {
	      namesz++;
	      fprintf (asm_out_file, " 0%c", namesz % 4 ? ',' : ' ');
	    }
	  annobin_emit_asm (NULL, "padding");
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

	  annobin_emit_asm (NULL, desc2 ? "description [symbol names]" : "description [symbol name]");

	  if (desc2)
	    {
	      if (annobin_is_64bit)
		fprintf (asm_out_file, "\t.quad %s\n", (char *) desc2);
	      else
		fprintf (asm_out_file, "\t.dc.l %s\n", (char *) desc2);
	    }
	}
      else
	{
	  fprintf (asm_out_file, "\t.dc.b");

	  for (i = 0; i < descsz; i++)
	    {
	      fprintf (asm_out_file, " %#x", ((unsigned char *) desc1)[i]);

	      if (i == (descsz - 1))
		annobin_emit_asm (NULL, "description");
	      else if ((i % 8) == 7)
		{
		  annobin_emit_asm (NULL, "description");
		  fprintf (asm_out_file, "\t.dc.b");
		}
	      else
		fprintf (asm_out_file, ",");
	    }

	  /* These notes use 4 byte alignment, even on 64-bit systems.  */
	  if (descsz % 4)
	    {
	      fprintf (asm_out_file, "\t.dc.b");
	      while (descsz % 4)
		{
		  descsz++;
		  fprintf (asm_out_file, " 0%c", descsz % 4 ? ',' : ' ');
		}
	      annobin_emit_asm (NULL, "padding");
	    }
	}
    }

  fprintf (asm_out_file, "\t.popsection\n\n");
  fflush (asm_out_file);

  ++ annobin_note_count;
}

/* Fills in the DESC1, DESC2 and DESCSZ parameters for a call to annobin_output_note.  */
#define DESC_PARAMETERS(DESC1, DESC2) \
  DESC1, DESC2, (DESC1) == NULL ? 0 : (DESC2 == NULL) ? (annobin_is_64bit ? 8 : 4) : (annobin_is_64bit ? 16 : 8)

void
annobin_output_static_note (const char *  buffer,
			    unsigned      buffer_len,
			    bool          name_is_string,
			    const char *  name_description,
			    const char *  start,
			    const char *  end,
			    unsigned      note_type,
			    const char *  sec_name)
{
  annobin_output_note (buffer, buffer_len, name_is_string, name_description,
		       DESC_PARAMETERS (start, end), true, note_type, sec_name);
}

void
annobin_output_bool_note (const char    bool_type,
			  const bool    bool_value,
			  const char *  name_description,
			  const char *  start,
			  const char *  end,
			  unsigned      note_type,
			  const char *  sec_name)
{
  char buffer [6];
  unsigned int len;

  len = sprintf (buffer, "GA%c%c", bool_value ? BOOL_T : BOOL_F, bool_type);

  /* Include the NUL byte at the end of the name string.
     This is required by the ELF spec.  */
  annobin_output_static_note (buffer, len + 1, false, name_description,
			      start, end, note_type, sec_name);
}

void
annobin_output_string_note (const char    string_type,
			    const char *  string,
			    const char *  name_description,
			    const char *  start,
			    const char *  end,
			    unsigned      note_type,
			    const char *  sec_name)
{
  unsigned int len = strlen (string);
  char * buffer;

  buffer = (char *) xmalloc (len + 5);

  sprintf (buffer, "GA%c%c%s", GNU_BUILD_ATTRIBUTE_TYPE_STRING, string_type, string);

  /* Be kind to readers of the assembler source, and do
     not put control characters into ascii strings.  */
  annobin_output_static_note (buffer, len + 5, ISPRINT (string_type), name_description,
			      start, end, note_type, sec_name);

  free (buffer);
}

void
annobin_output_numeric_note (const char     numeric_type,
			     unsigned long  value,
			     const char *   name_description,
			     const char *   start,
			     const char *   end,
			     unsigned       note_type,
			     const char *   sec_name)
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
    ice ("Numeric value too big to fit into 8 bytes");
  if (value)
    ice ("Unable to record numeric value");

  annobin_output_static_note (buffer, i + 1, false, name_description,
			      start, end, note_type, sec_name);
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
   the -O and -g options, and some -W options.  This is to help
   verify the recommended hardening options for binaries.
   The format of the number is as follows:

   bits 0 -  2 : debug type (from enum debug_info_type)
   bit  3      : with GNU extensions
   bits 4 -  5 : debug level (from enum debug_info_levels)
   bits 6 -  8 : DWARF version level
   bits 9 - 10 : optimization level
   bit  11     : -Os
   bit  12     : -Ofast
   bit  13     : -Og
   bit  14     : -Wall
   bit  15     : -Wformat-security  */

static unsigned int
compute_GOWall_options (void)
{
  unsigned int val, i;

  /* FIXME: Keep in sync with changes to gcc/flag-types.h:enum debug_info_type.  */
  if (write_symbols > VMS_AND_DWARF2_DEBUG)
    {
      annobin_inform (INFORM_VERBOSE, "write_symbols = %d", write_symbols);
      ice ("unknown debug info type");
      val = 0;
    }
  else
    val = write_symbols;

  if (use_gnu_debug_info_extensions)
    val |= (1 << 3);

  if (debug_info_level > DINFO_LEVEL_VERBOSE)
    {
      annobin_inform (INFORM_VERBOSE, "debug_info_level = %d", debug_info_level);
      ice ("unknown debug info level");
    }
  else
    val |= (debug_info_level << 4);

  if (dwarf_version < 2)
    {
      /* Apparently it is possible for dwarf_version to be -1.  Not sure how
	 this can happen, but handle it anyway.  Since DWARF prior to v2 is
	 deprecated, we use 2 as the version level.  */
      val |= (2 << 6);
      annobin_inform (INFORM_VERBOSE, "dwarf version level %d recorded as 2", dwarf_version);
    }
  else if (dwarf_version > 7)
    {
      /* FIXME: We only have 3 bits to record the debug level...  */
      val |= (7 << 6);
      annobin_inform (INFORM_VERBOSE, "dwarf version level %d recorded as 7", dwarf_version);
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

  /* -Wformat-security is enabled via -Wall, but we record it here because
     it is important, and because LTO compilation does not pass on the -Wall
     flag.  FIXME: Add other important warnings.  */
  if (warn_format_security)
    val|= (1 << 15);

  return val;
}

static void
record_GOW_settings (unsigned int gow,
		     bool local,
		     const char * cname,
		     const char * aname,
		     const char * aname_end,
		     const char * sec_name)
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
      annobin_inform (INFORM_VERBOSE, "Record -g/-O/-Wall status for %s", cname);
      annobin_output_note (buffer, i + 1, false, "numeric: -g/-O/-Wall",
			   DESC_PARAMETERS (aname, aname_end), true, FUNC, sec_name);
    }
  else
    {
      annobin_inform (INFORM_VERBOSE, "Record status of -g/-O/-Wall");
      annobin_output_note (buffer, i + 1, false, "numeric: -g/-O/-Wall",
			   NULL, NULL, 0, false, OPEN, sec_name);
    }
}

#ifdef flag_stack_clash_protection
static void
record_stack_clash_note (const char * start, const char * end, int type, const char * sec_name)
{
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%cstack_clash",
			  flag_stack_clash_protection ? BOOL_T : BOOL_F);

  annobin_output_static_note (buffer, len + 1, true, "bool: -fstack-clash-protection status",
			      start, end, type, sec_name);
}
#endif

#ifdef flag_cf_protection
static void
record_cf_protection_note (const char * start, const char * end, int type, const char * sec_name)
{
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%ccf_protection", NUMERIC);

  /* We bias the flag_cf_protection enum value by 1 so that we do not get confused by a zero value.  */
  buffer[++len] = flag_cf_protection + 1;
  buffer[++len] = 0;

  annobin_inform (INFORM_VERBOSE, "Record cf-protection status of %d", flag_cf_protection);
  annobin_output_static_note (buffer, len + 1, false, "numeric: -fcf-protection status",
			      start, end, type, sec_name);
}
#endif

static void
record_frame_pointer_note (const char * start, const char * end, int type, const char * sec_name)
{
  char buffer [128];
  unsigned len;

  if (flag_omit_frame_pointer)
    len = sprintf (buffer, "GA%comit_frame_pointer", BOOL_T);
  else
    len = sprintf (buffer, "GA%comit_frame_pointer", BOOL_F);

  annobin_inform (INFORM_VERBOSE, "Record omit-frame-pointer status of %d", flag_omit_frame_pointer);
  annobin_output_static_note (buffer, len + 1, true, "bool: -fomit-frame-pointer status",
			      start, end, type, sec_name);
}

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

static void
record_fortify_level (int level, int type, const char * sec)
{
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%cFORTIFY", NUMERIC);

  buffer[++len] = level;
  buffer[++len] = 0;
  annobin_output_note (buffer, len + 1, false, "FORTIFY SOURCE level",
		       NULL, NULL, 0, false, type, sec);
  annobin_inform (INFORM_VERBOSE, "Record a FORTIFY SOURCE level of %d", level);
}

static void
record_glibcxx_assertions (bool on, int type, const char * sec)
{
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%cGLIBCXX_ASSERTIONS", on ? BOOL_T : BOOL_F);

  annobin_output_note (buffer, len + 1, false, on ? "_GLIBCXX_ASSERTIONS defined" : "_GLIBCXX_ASSERTIONS not defined",
		       NULL, NULL, 0, false, type, sec);
  annobin_inform (INFORM_VERBOSE, "Record a _GLIBCXX_ASSERTIONS as %s", on ? "defined" : "not defined");
}

/* This structure provides various names associated with the current
   function.  The fields are computed in annobin_create_function_notes
   and consumed in various places.  */
typedef struct annobin_current_function
{
  const char * func_name;
  const char * asm_name;
  const char * section_name;
  const char * group_name;
  bool         comdat;
  const char * attribute_section_string;
  const char * start_sym;
  const char * end_sym;
  const char * unlikely_section_name;
  const char * unlikely_end_sym;
} annobin_current_function;

static annobin_current_function current_func;

static void
clear_current_func (void)
{
  free ((void *) current_func.func_name);
  free ((void *) current_func.asm_name);
  free ((void *) current_func.section_name);
  free ((void *) current_func.group_name);
  free ((void *) current_func.attribute_section_string);
  free ((void *) current_func.start_sym);
  free ((void *) current_func.end_sym);
  free ((void *) current_func.unlikely_section_name);
  free ((void *) current_func.unlikely_end_sym);

  memset (& current_func, 0, sizeof current_func);
}

static void
annobin_emit_function_notes (bool force)
{
  const char *  start_sym = current_func.start_sym;
  const char *  end_sym   = current_func.end_sym;
  const char *  sec_name  = current_func.attribute_section_string;
  const char *  func_name = current_func.func_name;
  
  unsigned int  count     = annobin_note_count;

  annobin_target_specific_function_notes (start_sym, end_sym, sec_name, force);

  /* If one or more notes were generated by the target specific function
     then we no longer need to include the start/end symbols in any
     futher notes that we gebenerate.  */
  if (annobin_note_count > count)
    start_sym = end_sym = NULL;

  if (flag_stack_protect != -1
      && (force
	  || global_stack_prot_option != flag_stack_protect))
    {
      annobin_inform (INFORM_VERBOSE, "Recording stack protection status of %d for %s",
		      flag_stack_protect, func_name);

      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_STACK_PROT, flag_stack_protect,
				   "numeric: -fstack-protector status",
				   start_sym, end_sym, FUNC, sec_name);

      /* We no longer need to include the symbols in the notes we generate.  */
      start_sym = end_sym = NULL;
    }

#ifdef flag_stack_clash_protection
  if (force
      || global_stack_clash_option != flag_stack_clash_protection)
    {
      annobin_inform (INFORM_VERBOSE, "Recording stack clash protection status of %d for %s",
		      flag_stack_clash_protection, func_name);

      record_stack_clash_note (start_sym, end_sym, FUNC, sec_name);
      start_sym = end_sym = NULL;
    }
#endif

#ifdef flag_cf_protection
  if (force
      || global_cf_option != flag_cf_protection)
    {
      annobin_inform (INFORM_VERBOSE, "Recording control flow protection status of %d for %s",
		      flag_cf_protection, func_name);

      record_cf_protection_note (start_sym, end_sym, FUNC, sec_name);
      start_sym = end_sym = NULL;
    }
#endif

  if (force || global_omit_frame_pointer != flag_omit_frame_pointer)
    {
      annobin_inform (INFORM_VERBOSE, "Recording omit_frame_pointer status of %d for %s",
		      flag_omit_frame_pointer, func_name);

      record_frame_pointer_note (start_sym, end_sym, FUNC, sec_name);
      start_sym = end_sym = NULL;
    }

  if (force
      || global_pic_option != compute_pic_option ())
    {
      annobin_inform (INFORM_VERBOSE, "Recording PIC status of %s", func_name);
      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_PIC, compute_pic_option (),
				   "numeric: pic type", start_sym, end_sym,
				   FUNC, sec_name);
      start_sym = end_sym = NULL;
    }

  if (force
      || global_GOWall_options != compute_GOWall_options ())
    {
      record_GOW_settings (compute_GOWall_options (), true, func_name, start_sym, end_sym, sec_name);
      start_sym = end_sym = NULL;
    }

  if (flag_short_enums != -1
      && (force
	  || global_short_enums != flag_short_enums))
    {
      annobin_inform (INFORM_VERBOSE, "Recording enum size for %s", func_name);
      annobin_output_bool_note (GNU_BUILD_ATTRIBUTE_SHORT_ENUM, flag_short_enums,
				flag_short_enums ? "bool: short-enums: on" : "bool: short-enums: off",
				start_sym, end_sym, FUNC, sec_name);
      start_sym = end_sym = NULL;
    }

  if (annobin_enable_stack_size_notes && flag_stack_usage_info)
    {
      if ((unsigned long) current_function_static_stack_size > stack_threshold)
	{
	  annobin_inform (INFORM_VERBOSE, "Recording stack usage of %lu for %s",
			  (unsigned long) current_function_static_stack_size,
			  func_name);

	  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_STACK_SIZE,
				       current_function_static_stack_size,
				       "numeric: stack-size",
				       start_sym, end_sym, FUNC, sec_name);
	  start_sym = end_sym = NULL;
	}

      annobin_total_static_stack_usage += current_function_static_stack_size;

      if ((unsigned long) current_function_static_stack_size > annobin_max_stack_size)
	annobin_max_stack_size = current_function_static_stack_size;
    }

  /* Always record the fortify and assertion levels as we cannot be sure that
     the global values have been recorded.  cf BZ 1703500.  */
  record_fortify_level (global_fortify_level, FUNC, sec_name);
  record_glibcxx_assertions (global_glibcxx_assertions, FUNC, sec_name);
}

static const char *
annobin_get_section_name (const_tree decl)
{
#if GCCPLUGIN_VERSION_MAJOR >= 5
  return DECL_SECTION_NAME (current_function_decl);
#else
  /* Prior to gcc version 5 DECL_SECTION_NAME returned a tree.  */
  const_tree name_decl = DECL_SECTION_NAME (current_function_decl);
  if (name_decl == NULL_TREE)
    return NULL;
  return TREE_STRING_POINTER (name_decl);
#endif
}

static struct cgraph_node *
annobin_get_node (const_tree decl)
{
#if GCCPLUGIN_VERSION_MAJOR >= 5
  return cgraph_node::get (decl);
#else
  /* Use old form for access node.  */
  return cgraph_get_node (decl);
#endif
}

static void
annobin_emit_symbol (const char * name)
{
  fprintf (asm_out_file, "\t.type %s, STT_NOTYPE\n", name);
  fprintf (asm_out_file, "\t.hidden %s\n", name);
  fprintf (asm_out_file, "%s:\n", name);
}

/* Create any notes specific to the current function.  */

static void
annobin_create_function_notes (void * gcc_data, void * user_data)
{
  unsigned int  count;
  bool          force;

  if (! annobin_enable_static_notes || asm_out_file == NULL)
    return;

  if (current_func.func_name != NULL)
    ice ("new function encountered whilst still processing old function");

  current_func.func_name = current_function_name ();
  current_func.asm_name  = function_asm_name ();

  if (current_func.func_name == NULL)
    {
      current_func.func_name = current_func.asm_name;

      if (current_func.func_name == NULL)
	{
	  /* Can this happen ?  */
	  ice ("function name not available");
	  return;
	}
    }

  if (current_func.asm_name == NULL)
    current_func.asm_name = current_func.func_name;

  /* Copy the names so that they are saved.  */
  current_func.func_name = concat (current_func.func_name, NULL);
  current_func.asm_name = concat (current_func.asm_name, NULL);
  
  struct cgraph_node * node = annobin_get_node (current_function_decl);
  bool startup, exit, unlikely, likely;

  if (node)
    {
      startup = node->only_called_at_startup;
      exit = node->only_called_at_exit;
      unlikely =  node->frequency == NODE_FREQUENCY_UNLIKELY_EXECUTED;
      likely = node->frequency == NODE_FREQUENCY_HOT;
    }
  else
    startup = exit = unlikely = likely = false;

  current_func.comdat = DECL_COMDAT_GROUP (current_function_decl) != NULL;
  
  current_func.section_name = annobin_get_section_name (current_function_decl);
  if (current_func.section_name != NULL)
    /* This is just so that we can free it later.  */
    current_func.section_name = concat (current_func.section_name, NULL);

  else if (current_func.comdat)
    {
      targetm.asm_out.unique_section (current_function_decl, 0);
      current_func.section_name = concat (annobin_get_section_name (current_function_decl), NULL);
    }

  else if (flag_function_sections)
    {
      /* Special case: at -O2 or higher special functions get a prefix added.  */
      if (flag_reorder_functions)
	{
          if (startup)
	    current_func.section_name = concat (STARTUP_SECTION, ".", current_func.asm_name, NULL);
          else if (exit)
	    current_func.section_name = concat (EXIT_SECTION, ".", current_func.asm_name, NULL);
          else if (unlikely)
	    current_func.section_name = concat (COLD_SECTION, ".", current_func.asm_name, NULL);
          else if (likely)
	    current_func.section_name = concat (HOT_SECTION, ".", current_func.asm_name, NULL);
	  else
	    {
	      current_func.section_name = concat (CODE_SECTION, ".", current_func.asm_name, NULL);
	      current_func.unlikely_section_name = concat (COLD_SECTION, ".", current_func.asm_name, NULL);
	    }
	 }
      else
	current_func.section_name = concat (CODE_SECTION, ".", current_func.asm_name, NULL);
    }

  else if (flag_reorder_functions /* && targetm_common.have_named_sections */)
    {
      /* Attempt to determine the section into which the code will be placed.
	 We could call targetm.asm_out_function_section but that ends up calling
	 get_section() which will *create* a section if none exists.  This causes
	 problems because later on gcc will attempt to create the section again
	 but this time it might be using different flags.

	 So instead we duplicate the code in gcc/varasm.c:default_function_section()
	 except that we do not actually call get_named_text_section().  */

      if (unlikely)
	{
	  /* FIXME: Never actually seen this case occur...  */
	  current_func.section_name = concat (COLD_SECTION, NULL);
	}
      else if (startup)
	{
	  if (!in_lto_p && ! flag_profile_values)
	    current_func.section_name = concat (STARTUP_SECTION, NULL);
	}
      else if (exit)
	{
	  current_func.section_name = concat (EXIT_SECTION, NULL);
	}
      else if (likely)
	{
	  /* FIXME: Never seen this one, either.  */
	  if (!in_lto_p && ! flag_profile_values)
	    current_func.section_name = concat (HOT_SECTION, NULL);
	}
    }

  annobin_inform (INFORM_VERBOSE, "Function '%s' is assumed to be in section '%s'",
		  current_func.asm_name,
		  current_func.section_name ? current_func.section_name : CODE_SECTION);

  /* If the function is going to be in its own section, then we do not know
     where it will end up in memory.  In particular we cannot rely upon it
     being included in the memory range covered by the global notes.  So for
     such functions we always generate a set of notes.

     FIXME: We do not currently generate a full range of notes.  */
  force = current_func.section_name != NULL;

  if (force)
    {
      if (current_func.comdat)
	current_func.group_name = concat (IDENTIFIER_POINTER (DECL_COMDAT_GROUP (current_function_decl)), NULL);
      else
	current_func.group_name = concat (current_func.section_name, ANNOBIN_GROUP_NAME, NULL);

      /* Include a group name in our attribute section name.  */
      current_func.attribute_section_string = concat (GNU_BUILD_ATTRS_SECTION_NAME, current_func.section_name,
						      ", \"G\", %note, ",
						      current_func.group_name,
						      current_func.comdat ? ", comdat" : "",
						      NULL);
    }
 else
   {
     if (current_func.comdat)
       ice ("current function is comdat but has no function section");

     current_func.group_name = NULL;
     current_func.attribute_section_string = concat (GNU_BUILD_ATTRS_SECTION_NAME, NULL);
   }

  /* We use our own function start and end symbols so that they will
     not interfere with the program proper.  In particular if we use
     the function name symbol ourselves then we can cause problems
     when the linker attempts to resolve relocs against it and finds
     that it has both PC relative and abolsute relocs.

     We try our best to ensure that the new symbols will not clash
     with any other symbols in the program.  */
  current_func.start_sym = concat (ANNOBIN_SYMBOL_PREFIX, current_func.asm_name, ".start", NULL);
  current_func.end_sym   = concat (ANNOBIN_SYMBOL_PREFIX, current_func.asm_name, ".end", NULL);

  count = annobin_note_count;
  annobin_emit_function_notes (force);

  if (annobin_note_count > count)
    {
      /* If we generated any notes then we must make sure that the start
	 symbol has been emitted as well.  The end symbols will be emitted
	 by annobin_create_function_end_symbol, once the body of the function
	 has been written to the assembler file.

	 Note we cannot just use ".equiv start_sym, asm_name", as the
	 assembler symbol might have a special type, eg ifunc, and this
	 would be inherited by our symbol.  */

      /* Switch to the code section.  Make sure that we declare the section
	 in the same way that gcc will declare it.  In particular note that
	 gcc will not add a group notation for non-comdat sections.  */
      if (current_func.section_name == NULL)
	fprintf (asm_out_file, "\t.pushsection %s\n", CODE_SECTION);
      else if (current_func.comdat)
	fprintf (asm_out_file, "\t.pushsection %s, \"axG\", %%progbits, %s, comdat\n",
		 current_func.section_name, current_func.group_name);
      else
	fprintf (asm_out_file, "\t.pushsection %s, \"ax\", %%progbits\n", current_func.section_name);

      /* Add the start symbol.  */
      annobin_emit_symbol (current_func.start_sym);
      fprintf (asm_out_file, "\t.popsection\n");
    }
  else
    {
      /* No notes were emitted.  We do not need the symbols or anything else.  */
      clear_current_func ();
      return;
    }

  if (current_func.unlikely_section_name)
    {
      const char * saved_end_sym;

      /* If there is a possibility that GCC might generate an cold section
	 variant of the current function section, then we need to annotate
	 that as well.  */
      
      current_func.start_sym = concat (ANNOBIN_SYMBOL_PREFIX, current_func.asm_name, ".start", COLD_SECTION, NULL);
      current_func.unlikely_end_sym   = concat (ANNOBIN_SYMBOL_PREFIX, current_func.asm_name, ".end", COLD_SECTION, NULL);

      saved_end_sym = current_func.end_sym;
      current_func.end_sym = current_func.unlikely_end_sym;
      annobin_emit_function_notes (true);

      /* Add the start symbol.  */
      fprintf (asm_out_file, "\t.pushsection %s, \"ax\", %%progbits\n",
	       current_func.unlikely_section_name);
      annobin_emit_symbol (current_func.start_sym);
      fprintf (asm_out_file, "\t.popsection\n");

      current_func.end_sym = saved_end_sym;
    }
}

typedef struct attach_item
{
  const char *          section_name;
  const char *          group_name;
  struct attach_item *  next;
} attach_item;

static attach_item * attach_list = NULL;
  
static void
queue_attachment (const char * section_name, const char * group_name)
{
  attach_item * item = (attach_item *) xmalloc (sizeof * item);

  item->section_name = concat (section_name, NULL);
 item->group_name = concat (group_name, NULL);
  item->next = attach_list;
  attach_list = item;
}

static void
emit_queued_attachments (void)
{
  if (!annobin_enable_attach)
    return;

  attach_item * item;
  attach_item * next = NULL;
  for (item = attach_list; item != NULL; item = next)
    {
      const char * name = item->section_name;

      fprintf (asm_out_file, "\t.pushsection %s\n", name);
      fprintf (asm_out_file, "\t.attach_to_group %s", item->group_name);
      if (flag_verbose_asm)
	fprintf (asm_out_file, " %s Add the %s section to the %s group",
		 ASM_COMMENT_START, name, item->group_name);
      fprintf (asm_out_file, "\n");
      fprintf (asm_out_file, "\t.popsection\n");

      // FIXME: BZ 1684148: These free()s are triggering "attempt to free unallocated
      // memory" errors from the address sanitizer.  I have no idea why, as they were
      // allocated by concat.  So for now, just leave them be.  The memory will be
      // released when gcc terminates.
      // free ((void *) item->section_name);
      // free ((void *) item->group_name);
      next = item->next;
      // FIXME: BZ #1638371 reports that this free() triggers an "invalid pointer"
      // error when running under MALLOC_CHECK_.  I have no idea why, as the
      // pointer certainly looks valid to me.  So for now, suppress the free.
      // free ((void *) item);
    }
}

static void
annobin_create_function_end_symbol (void * gcc_data, void * user_data)
{
  if (! annobin_enable_static_notes || asm_out_file == NULL)
    return;

  if (current_func.end_sym == NULL)
    return;

  /* Emit an end symbol for the code in the current function.
     First, we have to switch to the correct section.  */

  if (current_func.section_name == NULL)
    fprintf (asm_out_file, "\t.pushsection %s\n", CODE_SECTION);

  else if (current_func.comdat)
    fprintf (asm_out_file, "\t.pushsection %s, \"axG\", %%progbits, %s, comdat\n",
	     current_func.section_name, current_func.group_name);

  else
    {
      if (current_func.unlikely_section_name)
	{
	  /* Emit the end symbol in the unlikely section.
	     Note - we attempt to create a new section that will be appended to the
	     end of the sections that are going into the section group.  */
	  fprintf (asm_out_file, "\t.pushsection %s.zzz, \"ax\", %%progbits\n",
		   current_func.unlikely_section_name);
	  annobin_emit_symbol (current_func.unlikely_end_sym);
	  fprintf (asm_out_file, "\t.popsection\n");

	  /* Make sure that the unlikely section will be added into the
	     current function's group.  */
	  if (annobin_enable_attach)
	    queue_attachment (current_func.unlikely_section_name,
			      current_func.group_name);
	}

      fprintf (asm_out_file, "\t.pushsection %s\n", current_func.section_name);

      /* We have a problem.  We want to create a section group containing
	 the function section, the note section and the relocations.  But
	 we cannot just emit:

	 .section .text.foo, "axG", %%progbits, foo.group

	 because GCC will emit its own section definition, which does not
	 attach to a group:

	 .section .text.foo, "ax", %%progbits

	 This will create a *second* section called .text.foo, which is
	 *not* in the group.  The notes generated by annobin will be
	 attached to the group, but the code generated by gcc will not.

	 We cannot create a reference from the non-group'ed section
	 to the group'ed section as this will create a DT_TEXTREL entry
	 (ie dynamic text relocation) which is not allowed.

	 We cannot access GCC's section structure and set the
	 SECTION_DECLARED flag as the hash tab holding the structures is
	 private to the varasm.c file.

	 We cannot intercept the asm_named_section() function in GCC as
	 this is defined by the TARGET_ASM_NAMED_SECTION macro, rather
	 than being defined in the target structure.

	 If we omit the section group then the notes will work for
	 retained sections, but they will not be removed for any garbage
	 collected code.  So then you will have notes covering address
	 ranges that are probably used for something else.

	 The solution for now is to attach GCC's .text.foo section to the
	 group created for annobin's .text.foo section by using a new
	 assembler pseudo-op.  This can be disabled to allow the plugin
	 to work with older assemblers, although it does mean that notes
	 for function sections will be discarded by the linker.

	 Note - we do not have to do this for COMDAT sections as they are
	 already part of a section group, and gcc always includes the group
	 name in its .section directives.

	 Note - we do not emit these attach directives here as function
	 sections can be reused.  So instead we accumulate them and issue
	 them all at the end of compilation.  */
      if (annobin_enable_attach)
	queue_attachment (current_func.section_name, current_func.group_name);
    }

  annobin_inform (INFORM_VERBOSE, "Function '%s' is assumed to end in section '%s'",
		  current_func.asm_name,
		  current_func.section_name ? current_func.section_name : CODE_SECTION);

  annobin_emit_symbol (current_func.end_sym);
  fprintf (asm_out_file, "\t.popsection\n");

  clear_current_func ();
}

static void
annobin_emit_start_sym_and_version_note (const char * suffix,
					 const char   producer_char)
{
  if (* suffix)
    {
      if (annobin_enable_attach)
	/* We put suffixed text sections into a group so that the linker
	   can delete the notes if the code is discarded.  */
	fprintf (asm_out_file, "\t.pushsection %s%s, \"axG\", %%progbits, %s%s%s\n",
		 CODE_SECTION, suffix,
		 CODE_SECTION, suffix, ANNOBIN_GROUP_NAME);
      else
	fprintf (asm_out_file, "\t.pushsection %s%s, \"ax\", %%progbits\n",
		 CODE_SECTION, suffix);
    }
  else
    fprintf (asm_out_file, "\t.pushsection %s\n", CODE_SECTION);

  fprintf (asm_out_file, "\t%s %s%s\n", global_file_name_symbols ? ".global" : ".hidden",
	   annobin_current_filename, suffix);

  /* Note - we used to set the type of the symbol to STT_OBJECT, but that is
     incorrect because that type is for:
       "A data object, such as a variable, an array, and so on".

     There is no ELF symbol to represent a compilation unit, (STT_FILE only
     covers a single source file and has special sematic requirements), so
     instead we use STT_NOTYPE.  (Ideally we could use STT_LOOS+n, but there
     is a problem with the GAS assembler, which does not allow such values to
     be set on symbols).  */
  fprintf (asm_out_file, "\t.type %s%s, STT_NOTYPE\n", annobin_current_filename, suffix);

  if (target_start_sym_bias)
    {
      /* We set the address of the start symbol to be the current address plus
	 a bias value.  That way this symbol will not be confused for a file
	 start/function start symbol.

	 There is special code in annobin_output_note() that undoes this bias
	 when the symbol's address is being used to compute a range for the
	 notes.  */
      fprintf (asm_out_file, "\t.set %s%s, . + %d\n", annobin_current_filename, suffix, target_start_sym_bias);
    }
  else
    fprintf (asm_out_file, "\t.equiv %s%s, .\n", annobin_current_filename, suffix);

  /* We explicitly set the size of the symbol to 0 so that it will not
     confuse other tools (eg GDB, elfutils) which look for symbols that
     cover an address range.  */
  fprintf (asm_out_file, "\t.size %s%s, 0\n", annobin_current_filename, suffix);

  fprintf (asm_out_file, "\t.popsection\n");

  const char * start = concat (annobin_current_filename, suffix, NULL);
  const char * end = concat (annobin_current_endname, suffix, NULL);
  const char * sec;

  if (* suffix)
    sec = concat (GNU_BUILD_ATTRS_SECTION_NAME, suffix,
		  ", \"G\", %note, " CODE_SECTION, suffix, ANNOBIN_GROUP_NAME, NULL);
  else
    sec = concat (GNU_BUILD_ATTRS_SECTION_NAME, suffix, NULL);

  char buffer [124];

  sprintf (buffer, "%d%c%d", SPEC_VERSION, producer_char, annobin_version);
  annobin_output_string_note (GNU_BUILD_ATTRIBUTE_VERSION, buffer,
			      "string: version", start, end, OPEN, sec);

  free ((void *) sec);
  free ((void *) end);
  free ((void *) start);
}

static void
emit_global_notes (const char * suffix)
{
  const char * sec = concat (GNU_BUILD_ATTRS_SECTION_NAME, suffix, NULL);

  annobin_inform (INFORM_VERBOSE, "Emit global notes for section .text%s...", suffix);

  /* Record the version of the compiler.  */
  annobin_inform (INFORM_VERBOSE, "Annobin compiler versions: %s, %s", build_version, run_version);
  annobin_output_string_note (GNU_BUILD_ATTRIBUTE_TOOL, run_version,
			      "string: build-tool", NULL, NULL, OPEN, sec);
  annobin_output_string_note (GNU_BUILD_ATTRIBUTE_TOOL, build_version,
			      "string: build-tool", NULL, NULL, OPEN, sec);

  /* Record optimization level, -W setting and -g setting  */
  record_GOW_settings (global_GOWall_options, false, NULL, NULL, NULL, sec);

  /* Record -fstack-protector option.  */
  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_STACK_PROT,
			       /* See BZ 1563141 for an example where global_stack_protection can be -1.  */
			       global_stack_prot_option >= 0 ? global_stack_prot_option : 0,
			       "numeric: -fstack-protector status",
			       NULL, NULL, OPEN, sec);
  annobin_inform (INFORM_VERBOSE, "Record stack protector setting of %d", global_stack_prot_option >= 0 ? global_stack_prot_option : 0);

#ifdef flag_stack_clash_protection
  /* Record -fstack-clash-protection option.  */
  record_stack_clash_note (NULL, NULL, OPEN, sec);
#endif
#ifdef flag_cf_protection
  /* Record -fcf-protection option.  */
  record_cf_protection_note (NULL, NULL, OPEN, sec);
#endif

  record_fortify_level (global_fortify_level, OPEN, sec);
  record_glibcxx_assertions (global_glibcxx_assertions, OPEN, sec);

  /* Record the PIC status.  */
  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_PIC, global_pic_option,
			       "numeric: PIC", NULL, NULL, OPEN, sec);

  /* Record enum size.  */
  annobin_output_bool_note (GNU_BUILD_ATTRIBUTE_SHORT_ENUM, global_short_enums != 0,
			    global_short_enums != 0 ? "bool: short-enums: on" : "bool: short-enums: off",
			    NULL, NULL, OPEN, sec);

  record_frame_pointer_note (NULL, NULL, OPEN, sec);

  /* Building code with profiling, instrumentation or sanitization enabled
     can slow it down.  (cf PR 1753918).  Whilst this may be desireable
     during development it is probably a bad idea when creating production
     binaries.  So emit a note that can be detected and reported by annocheck.

     NB/ Since this is not a security feature we do not emit a note if none
     of these options are enabled.  This helps to minimize the size of the
     annobin data.

     FIXME: At the moment we do not check to see if any of these flags change
     on a per-function basis.  */
  if (flag_instrument_function_entry_exit
#ifdef flag_sanitize
      || flag_sanitize
#endif
      || profile_flag
      || profile_arc_flag)
    {
      char buffer[128];
      unsigned int len = sprintf (buffer, "GA%cINSTRUMENT:%u/%u/%u/%u",
				  GNU_BUILD_ATTRIBUTE_TYPE_STRING,
#ifdef flag_sanitize
				  flag_sanitize,
#else
				  0,
#endif
				  flag_instrument_function_entry_exit,
				  profile_flag, profile_arc_flag);
      annobin_inform (INFORM_VERBOSE,
		      "Instrumentation options enabled: sanitize: %u, function entry/exit: %u, profiling: %u, profile arcs: %u",
#ifdef flag_sanitize
		      flag_sanitize,
#else
		      0,
#endif
		      flag_instrument_function_entry_exit,
		      profile_flag, profile_arc_flag);

      annobin_output_note (buffer, len + 1, true, "string: details of profiling enablement",
			   NULL, NULL, 0, false, OPEN, sec);
    }

  /* Record target specific notes.  */
  annobin_record_global_target_notes (sec);

  free ((void *) sec);
}

static void
annobin_create_global_notes (void * gcc_data, void * user_data)
{
  if (! annobin_enable_static_notes)
    return;

  if (asm_out_file == NULL)
    {
      /* This happens during LTO compilation.  Compilation is triggered
	 before any output file has been opened.  Since we do not have
	 the file handle we cannot emit any notes.  On the other hand,
	 the recompilation process will repeat later on with a real
	 output file and so the notes can be generated then.  */
      annobin_inform (INFORM_VERBOSE, "Output file not available - unable to generate notes");
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
      annobin_inform (INFORM_VERBOSE, "Pointer size: %d", POINTER_SIZE);
      ice ("Unknown target pointer size");
      return;
    }

  if (annobin_enable_stack_size_notes)
    /* We must set this flag in order to obtain per-function stack usage info.  */
    flag_stack_usage_info = 1;

#ifdef flag_stack_clash_protection
  global_stack_clash_option = flag_stack_clash_protection;
#endif
#ifdef flag_cf_protection
  global_cf_option = flag_cf_protection;
  if (annobin_active_checks && ((flag_cf_protection & CF_FULL) == 0))
    error ("-fcf-protection=full needed");
#endif
  global_stack_prot_option = flag_stack_protect;
  global_pic_option = compute_pic_option ();
  global_short_enums = flag_short_enums;
  global_GOWall_options = compute_GOWall_options ();
  global_omit_frame_pointer = flag_omit_frame_pointer;

  if (annobin_active_checks && optimize < 2 && ! optimize_debug)
    error ("optimization level is too low!");
  
  /* Output a file name symbol to be referenced by the notes...  */
  if (annobin_current_filename == NULL)
    init_annobin_current_filename ();
  if (annobin_current_filename == NULL)
    {
      ice ("Could not find output filename");
      /* We need a filename, so invent one.  */
      annobin_current_filename = (char *) "unknown_source";
    }

  /* Look for -D _FORTIFY_SOURCE=<n> and -D_GLIBCXX_ASSERTIONS on the
     original gcc command line.  Scan backwards so that we record the
     last version of the option, should multiple versions be set.  */

#define FORTIFY_OPTION "_FORTIFY_SOURCE"
#define GLIBCXX_OPTION "_GLIBCXX_ASSERTIONS"

  int i;

  for (i = save_decoded_options_count; i--;)
    {
      if (save_decoded_options[i].opt_index == OPT_U)
	{
	  if (save_decoded_options[i].arg == NULL)
	    continue;

	  annobin_inform (2, "decoded arg -U%s", save_decoded_options[i].arg);

	  if (strncmp (save_decoded_options[i].arg, FORTIFY_OPTION, strlen (FORTIFY_OPTION)) == 0)
	    {
	      if (global_fortify_level == -1)
		global_fortify_level = 0;
	    }
	  else if (strncmp (save_decoded_options[i].arg, GLIBCXX_OPTION, strlen (GLIBCXX_OPTION)) == 0)
	    {
	      if (global_glibcxx_assertions == -1)
		global_glibcxx_assertions = false;
	    }
	}
      else if (save_decoded_options[i].opt_index == OPT_D)
	{
	  if (save_decoded_options[i].arg == NULL)
	    continue;

	  annobin_inform (2, "decoded arg -D%s", save_decoded_options[i].arg);

	  if (strncmp (save_decoded_options[i].arg, FORTIFY_OPTION, strlen (FORTIFY_OPTION)) == 0)
	    {
	      int level = atoi (save_decoded_options[i].arg + strlen (FORTIFY_OPTION) + 1);

	      if (level < 0 || level > 3)
		{
		  annobin_inform (INFORM_ALWAYS, "Unexpected value in -D" FORTIFY_OPTION "%s",
				  save_decoded_options[i].arg);
		  level = 0;
		}

	      if (global_fortify_level == -1)
		global_fortify_level = level;
	    }

	  else if (strncmp (save_decoded_options[i].arg, GLIBCXX_OPTION, strlen (GLIBCXX_OPTION)) == 0)
	    {
	      if (global_glibcxx_assertions == -1)
		global_glibcxx_assertions = true;
	    }
	}
    }

  if (global_fortify_level == -1 || global_glibcxx_assertions == -1)
    {
      /* Not all gcc command line options get passed on to cc1 (or cc1plus).
	 So if we have not see one of the options that interests us we check
	 the COLLECT_GCC_OPTIONS environment variable instead.  */
      const char * cgo = getenv ("COLLECT_GCC_OPTIONS");

      if (cgo != NULL)
	{
	  if (global_fortify_level == -1)
	    {
	      int level = -1;
	      const char * fort = cgo;

	      while ((fort = strstr (fort, FORTIFY_OPTION)) != NULL)
		{
		  const char * next_fort = fort + strlen (FORTIFY_OPTION);

		  if (fort[-1] == 'U')
		    level = 0;
		  else
		    level = atoi (next_fort + 1);

		  fort = next_fort;
		}

	      if (level != -1)
		{
		  if (level < 0 || level > 3)
		    {
		      annobin_inform (INFORM_ALWAYS, "Unexpected value in -D" FORTIFY_OPTION);
		      level = 0;
		    }

		  global_fortify_level = level;
		}
	    }

	  if (global_glibcxx_assertions == -1)
	    {
	      int on = -1;
	      const char * glca = cgo;

	      while ((glca = strstr (glca, GLIBCXX_OPTION)) != NULL)
		{
		  if (glca[-1] == 'U')
		    on = false;
		  else
		    on = true;

		  glca = glca + strlen (GLIBCXX_OPTION);
		}

	      if (on != -1)
		global_glibcxx_assertions = on;
	    }
	}
    }

  if (in_lto_p)
    {
      /* In LTO mode the preprocessed options are not passed on.
	 For now, assume that they were present when the original object files
	 were compiled.
	 
	 FIXME: What we should do is examine the input object files and
	 extract the fortify and glibcxx notes from them.  But I do not know
	 if one plugin can access the data in another one...  */
      if (global_fortify_level == -1)
	global_fortify_level = 2;
      if (global_glibcxx_assertions == -1)
	global_glibcxx_assertions = 1;
    }
  else if (flag_generate_lto)
    {
      /* Because of the hack above, if we know that we are generating a
	 lto object file and the preprocessor values are insufficient,
	 then we generate a warning message for the user.  */
      if (global_fortify_level != 2)
	{
	  if (global_fortify_level == -1)
	    annobin_inform (INFORM_ALWAYS, _("Warning: -D_FORTIFY_SOURCE not defined"));
	  else
	    annobin_inform (INFORM_ALWAYS, _("Warning: -D_FORTIFY_SOURCE defined as %d"), global_fortify_level);
	}
      if (global_glibcxx_assertions != 1)
	{
	  annobin_inform (INFORM_ALWAYS, _("Warning: -D_GLIBCXX_ASSERTIONS not defined"));
	}
    }

  /* It is possible that no code will end up in the .text section.
     Eg because the compilation was run with the -ffunction-sections option.
     Nevertheless we generate this symbol in the .text section
     as at this point we cannot know which section(s) will be used
     by compiled code.  */
  annobin_emit_start_sym_and_version_note ("", 'p');
  emit_global_notes ("");

  /* GCC does not provide any way for a plugin to detect if hot/cold partitioning
     will be performed on a function, and hence a .text.hot and/or .text.unlikely
     section will be created.  So instead we create global notes to cover these
     two sections.  */
  annobin_emit_start_sym_and_version_note (HOT_SUFFIX, 'h');
  queue_attachment (HOT_SECTION, concat (HOT_SECTION, ANNOBIN_GROUP_NAME, NULL));
  //  emit_global_notes (HOT_SUFFIX);

  annobin_emit_start_sym_and_version_note (COLD_SUFFIX, 'c');
  queue_attachment (COLD_SECTION, concat (COLD_SECTION, ANNOBIN_GROUP_NAME, NULL));
  //  emit_global_notes (COLD_SUFFIX);

  /* *sigh* As of gcc 9, a .text.startup section can also be created.  */
  annobin_emit_start_sym_and_version_note (STARTUP_SUFFIX, 's');
  queue_attachment (COLD_SECTION, concat (STARTUP_SECTION, ANNOBIN_GROUP_NAME, NULL));
  //  emit_global_notes (STARTUP_SUFFIX);

  /* Presumably a .text.exit section can also be created, although I have not seen that yet.  */
  annobin_emit_start_sym_and_version_note (EXIT_SUFFIX, 'e');
  queue_attachment (COLD_SECTION, concat (EXIT_SECTION, ANNOBIN_GROUP_NAME, NULL));
  //  emit_global_notes (EXIT_SUFFIX);
}

static void
annobin_emit_end_symbol (const char * suffix)
{
  if (*suffix)
    {
      fprintf (asm_out_file, "\t.pushsection %s%s\n", CODE_SECTION, suffix);

      /* We want the end symbol to appear at the end of the section.
	 But if we are creating a symbol for the hot or cold sections
	 then there can be multiple copies of this section (with the
	 same name and identical attributes)!  So we create a *new*
	 section just for the end symbol.  The linker's normal section
	 concatenation heuristic should then place this section after
	 all the others.

	 Note however that it we are reversing a symbol bias we cannot
	 do this, as the arithmetic has to be between symbols defined
	 in the same section.  Fortunately it appears that gcc does not
	 perform hot/cold partitioning for the PPC64, and this is the
	 only target that uses symbol biasing.  */
      const char * extra_suffix = target_start_sym_bias ? "" : ".zzz";
	
      if (annobin_enable_attach)
	/* Since we have issued the .attach, make sure that we include the group here.  */
	fprintf (asm_out_file, "\t.section %s%s%s, \"axG\", %%progbits, %s%s%s\n",
		 CODE_SECTION, suffix, extra_suffix,
		 CODE_SECTION, suffix, ANNOBIN_GROUP_NAME);
      else
	fprintf (asm_out_file, "\t.section %s%s%s\n", CODE_SECTION, suffix, extra_suffix);
    }
  else
    fprintf (asm_out_file, "\t.pushsection %s\n", CODE_SECTION);

  fprintf (asm_out_file, "\t%s %s%s\n",
	   global_file_name_symbols ? ".global" : ".hidden",
	   annobin_current_endname, suffix);
  fprintf (asm_out_file, "%s%s:\n", annobin_current_endname, suffix);
  fprintf (asm_out_file, "\t.type %s%s, STT_NOTYPE\n", annobin_current_endname, suffix);
  fprintf (asm_out_file, "\t.size %s%s, 0\n", annobin_current_endname, suffix);

  /* If there is a bias to the start symbol, we can end up with the case where
     the start symbol is after the end symbol.  (If the section is empty).
     Catch that and adjust the start symbol.  This also pacifies eu-elflint
     which complains about the start symbol being placed beyond the end of
     the section.  */
  if (target_start_sym_bias)
    {
      /* Note: we cannot test "start sym > end sym" as these symbols may not have values
	 yet, (due to the possibility of linker relaxation).  But we are allowed to
	 test for symbol equality.  So we fudge things a little....  */
     
      fprintf (asm_out_file, "\t.if %s%s == %s%s + 2\n", annobin_current_filename, suffix,
	       annobin_current_endname, suffix);
      fprintf (asm_out_file, "\t  .set %s%s, %s%s\n", annobin_current_filename, suffix,
	       annobin_current_endname, suffix);
      fprintf (asm_out_file, "\t.endif\n");
    }

  fprintf (asm_out_file, "\t.popsection\n");
}

static void
annobin_create_loader_notes (void * gcc_data, void * user_data)
{
  if (asm_out_file == NULL)
    return;

  if (annobin_enable_static_notes)
    {
      /* It is possible that there is no code in the .text section.
	 Eg because the compilation was run with the -ffunction-sections option.
	 Nevertheless we generate this symbol because it is needed by the
	 version note that was generated in annobin_create_global_notes().  */
      if (annobin_enable_attach)
	emit_queued_attachments ();

      annobin_emit_end_symbol ("");
      annobin_emit_end_symbol (HOT_SUFFIX);
      annobin_emit_end_symbol (COLD_SUFFIX);
      annobin_emit_end_symbol (STARTUP_SUFFIX);
      annobin_emit_end_symbol (EXIT_SUFFIX);
    }

  if (! annobin_enable_dynamic_notes)
    return;

  if (annobin_enable_stack_size_notes && annobin_total_static_stack_usage)
    {
      annobin_inform (INFORM_VERBOSE, "Recording total static usage of %ld", annobin_total_static_stack_usage);

      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_STACK_SIZE, annobin_total_static_stack_usage,
				   "numeric: stack-size", NULL, NULL, OPEN, GNU_BUILD_ATTRS_SECTION_NAME);
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
      if (streq (key, "disable"))
	enabled = false;

      /* Private option used to allow building of the plugin whilst
	 another version of the plugin is also active.  */
      else if (streq (key, "rename"))
	annobin_extra_prefix = ".1";

      else if (streq (key, "enable"))
	enabled = true;

      else if (streq (key, "help"))
	annobin_inform (INFORM_ALWAYS, "%s", help_string);

      else if (streq (key, "version"))
	annobin_inform (INFORM_ALWAYS, "%s", version_string);

      else if (streq (key, "verbose"))
	verbose_level ++;

      else if (streq (key, "function-verbose"))
	annobin_function_verbose = true;

      else if (streq (key, "global-file-syms"))
	global_file_name_symbols = true;
      else if (streq (key, "no-global-file-syms"))
	global_file_name_symbols = false;

      else if (streq (key, "stack-size-notes"))
	annobin_enable_stack_size_notes = true;
      else if (streq (key, "no-stack-size-notes"))
	annobin_enable_stack_size_notes = false;

      else if (streq (key, "dynamic-notes"))
	annobin_enable_dynamic_notes = true;
      else if (streq (key, "no-dynamic-notes"))
	annobin_enable_dynamic_notes = false;

      else if (streq (key, "static-notes"))
	annobin_enable_static_notes = true;
      else if (streq (key, "no-static-notes"))
	annobin_enable_static_notes = false;

      else if (streq (key, "attach"))
	annobin_enable_attach = true;
      else if (streq (key, "no-attach"))
	annobin_enable_attach = false;

      else if (streq (key, "active-checks"))
	annobin_active_checks = true;
      else if (streq (key, "no-active-checks"))
	annobin_active_checks = false;

      else if (streq (key, "stack-threshold"))
	{
	  stack_threshold = strtoul (argv[argc].value, NULL, 0);
	  if (stack_threshold == 0)
	    stack_threshold = DEFAULT_THRESHOLD;
	}

      else
	{
	  /* Use fprintf here rather than annobin_inform as the latter
	     references main_input_filename, which is a gcc variable and
	     may not be accessible.  */
	  fprintf (stderr, "annobin: unrecognised option: %s\n", argv[argc].key);
	  return false;
	}
    }

  return true;
}

int
plugin_init (struct plugin_name_args *    plugin_info,
             struct plugin_gcc_version *  version)
{
  plugin_name = plugin_info->base_name;

  /* Parse args before checking version details so that we know if we need to be verbose.  */
  if (! parse_args (plugin_info->argc, plugin_info->argv))
    {
      annobin_inform (INFORM_VERBOSE, _("failed to parse arguments to the plugin"));
      return 1;
    }

  if (! enabled)
    return 0;

  if (!plugin_default_version_check (version, & gcc_version))
    {
      /* Note - we use fprintf here rather than annobin_inform as the
	 latter references main_input_filename, which is a gcc variable
	 and may not be accessible.  */
      bool fail = false;

      /* plugin_default_version_check is very strict and requires that the
	 major, minor and revision numbers all match.  Since annobin only
	 lightly touches gcc we assume that major number compatibility will
	 be sufficient.  [FIXME: It turns out that this is not entirely true...]  */
      if (strncmp (version->basever, gcc_version.basever, strchr (version->basever, '.') - version->basever))
	{
	  fprintf (stderr, _("annobin: Error: plugin built for compiler version (%s) but run with compiler version (%s)\n"),
		   gcc_version.basever, version->basever);
	  fail = true;
	}

      /* Since the plugin is not part of the gcc project, it is entirely
	 likely that it has been built on a different day.  This is not
	 a showstopper however, since compatibility will be retained as
	 long as the correct headers were used.  */
      if (BE_VERBOSE && ! streq (version->datestamp, gcc_version.datestamp))
	fprintf (stderr, _("annobin: Plugin datestamp (%s) is different from compiler datestamp (%s) - ignored\n"),
		 version->datestamp, gcc_version.datestamp);

      /* Unlikely, but also not serious.  */
      if (BE_VERBOSE && ! streq (version->devphase, gcc_version.devphase))
	fprintf (stderr, _("annobin: Plugin built for compiler development phase (%s) not (%s) - ignored\n"),
		 version->devphase, gcc_version.devphase);

      /* Theoretically this could be a problem, in practice it probably isn't.  */
      if (BE_VERBOSE && ! streq (version->revision, gcc_version.revision))
	fprintf (stderr, _("annobin: Plugin built for compiler revision (%s) not (%s) - ignored\n"),
		 version->revision, gcc_version.revision);

      if (! streq (version->configuration_arguments, gcc_version.configuration_arguments))
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
	      fprintf (stderr, _("annobin: Error: plugin run on a %.*s compiler but built for a %.*s compiler\n"),
		       (int) (plugin_target_end - plugin_target), plugin_target,
		       (int) (gcc_target_end - gcc_target), gcc_target);
	      fail = true;
	    }
	  else if (BE_VERBOSE)
	    {
	      fprintf (stderr, _("annobin: Plugin run on a compiler configured as (%s) not (%s) - ignored\n"),
		       version->configuration_arguments, gcc_version.configuration_arguments);
	    }
	}

      if (fail)
	return 1;
    }
  
  if (! annobin_enable_dynamic_notes && ! annobin_enable_static_notes)
    {
      annobin_inform (INFORM_VERBOSE, _("nothing to be done"));
      return 0;
    }

  // Almost everything of interest to annobin is held in the global_options
  // structure.  Make sure that this structure has not changed in size between
  // the time that this code was compiled and the time that the plugin is run.
  Dl_info info = { 0 };
  if (sizeof (plugin_info) == 4)
    {
      // We are running on a 32-bit host.
      Elf32_Sym * extra = NULL;
  
      if (dladdr1 (& global_options, & info, (void **) & extra, RTLD_DL_SYMENT) == 0)
	annobin_inform (INFORM_VERBOSE, "Failed to run dladdr1 on global_options");
      else if (extra == NULL)
	annobin_inform (INFORM_VERBOSE, "Failed to obtain extra information about global_options");
      else if (sizeof (global_options) != extra->st_size)
	{
	  ice ("The size of the global_options structure has changed - please rebuild annobin");
	  annobin_inform (INFORM_ALWAYS, "Build time size: %#x run time size: %#x (32-bit host)",
			  sizeof (global_options), extra->st_size);
	  return 1;
	}
    }
  else
    {
      // We are running on a 64-bit host.
      Elf64_Sym * extra = NULL;
  
      if (dladdr1 (& global_options, & info, (void **) & extra, RTLD_DL_SYMENT) == 0)
	annobin_inform (INFORM_VERBOSE, "Failed to run dladdr1 on global_options");
      else if (extra == NULL)
	annobin_inform (INFORM_VERBOSE, "Failed to obtain extra information about global_options");
      else if (sizeof (global_options) != extra->st_size)
	{
	  ice ("The size of the global_options structure has changed - please rebuild annobin");
	  annobin_inform (INFORM_ALWAYS, "Build time size: %#x run time size: %#x (64-bit host)",
			  sizeof (global_options), extra->st_size);
	  return 1;
	}
    }

  /* Record global compiler options.
     NB/ The format of these strings is important, as knowledge
     of their layout is embedded into hardended.c.  */
  run_version   = concat ("running gcc ", version->basever, " ", version->datestamp, NULL);
  build_version = concat ("annobin gcc ", gcc_version.basever, " ", gcc_version.datestamp, NULL);

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
