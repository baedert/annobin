/* annobin - a gcc plugin for annotating binary files.
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

#include <stdarg.h>
#include <stdio.h>
#include <intl.h>

#include "annobin-global.h"
#include "annobin.h"

/* Accessing the global_options structure is only permitted via annobin's version.  */
#undef  global_options
struct gcc_options * annobin_global_options = & global_options;
#define global_options ANNOBIN_ILLEGAL_GLOBAL_OPTIONS       

/* Version number.  */
#define xstr(s) str(s)
#define str(s)  #s
static unsigned int   annobin_version = ANNOBIN_VERSION;
static const char *   version_string = "Version " xstr(ANNOBIN_VERSION);

/* Prefix used to isolate annobin symbols from program symbols.  */
#define ANNOBIN_SYMBOL_PREFIX ".annobin_"

/* Filename to use when in LTO mode and the original filename is unavailable.  */
#define ANNOBIN_LTO_FIXED_NAME "lto"

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

#define LINKONCE_SEC_PREFIX ".gnu.linkonce."

/* Required by the GCC plugin API.  */
int            plugin_is_GPL_compatible;

/* True if this plugin is enabled.  Disabling is permitted so that build
   systems can globally enable the plugin, and then have specific build
   targets that disable the plugin because they do not want it.  */
static bool    enabled = true;

/* Enable a workaround for problems building elfutils for the PPC64.
   Inserts extra NOP instructions into the generated code.  */
static bool    enable_ppc64_nops = true;

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

/* 1 if annobin should generate gcc warnings if gcc command line options are wrong.
   2 if it should generate errors.
   0 if it should do nothing.  */
static uint           annobin_active_checks = 1;

/* Default to using section groups as the link-order
   method needs a linker from binutils 2.36 or later.  */
attach_type annobin_attach_type = not_set;

#ifdef flag_stack_clash_protection
static int            global_stack_clash_option = -1;
#endif
#ifdef flag_cf_protection
static int            global_cf_option = -1;
#endif
static bool           global_omit_frame_pointer;
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
static char *         annobin_output_filesym = NULL;
static const char *   annobin_input_filename = NULL;
static char *         annobin_current_endname  = NULL;
static const char *   help_string =  N_("Supported options:\n\
   disable                Disable this plugin\n\
   enable                 Enable this plugin\n\
   help                   Print out this information\n\
   version                Print out the version of the plugin\n\
   verbose                Be talkative about what is going on\n\
   function-verbose       Report the creation of function specific notes\n\
   [no-]active-checks     Do [do not] generate errors if gcc command line options are wrong.  (Default: warn)\n\
   [no-]attach            Do [do not] attempt to attach function sections to group sections\n\
   [no-]global-file-syms  Create global [or local] file name symbols (default: local)\n\
   [no-]link-order        Do [do not] attempt to join note sections to code sections using link_order attributes\n\
   [no-]ppc64-nops        Do [do not] insert NOP instructions into some PPC64 sections.  (Default: do not)\n\
   [no-]stack-size-notes  Do [do not] create stack size notes (default: do not)\n\
   rename                 Add a prefix to the filename symbols so that two annobin plugins can be active at the same time\n\
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

  if (annobin_input_filename)
    fprintf (stderr, "%s: ", annobin_input_filename);

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

bool
in_lto (void)
{
  /* Testing in_lto_p is unreliable because flag_lto does not appear in the cl_vars array.  */
  if (streq (progname, "lto1"))
    return true;

  if (streq (progname, "cc1") || streq (progname, "cc1plus"))
    return false;

  return GET_INT_OPTION_BY_NAME (in_lto_p) == 1;
}
    
/* Determine the (main) input file name.  */

static bool
init_annobin_input_filename (void)
{
  const char * f = NULL;

  /* In LTO mode the compiler will use a random string for the
     filename.  In order to allow for reproducible compilation
     however we must ensure that we use a fixed name.  */
  if (in_lto ())
    f = ANNOBIN_LTO_FIXED_NAME;
     
  /* Unfortunately we cannot rely upon 'main_input_filename' since
     if the input is preprocessed, this will have been set to the
     original un-preprocessed filename (foo.c) based upon the
     "# <line> <file>" comments in the preprocessed input (foo.i).
     Also main_input_filename is stored in the global_options array,
     where its offset cannot be safely determined.  */
  if (f == NULL && num_in_fnames > 0)
    f = in_fnames[0];

  if (f == NULL)
    /* This might fail, if annobin is out of sync with gcc.  */
    f = GET_STR_OPTION_BY_NAME (main_input_filename);

  annobin_input_filename = f;
  return f != NULL;
}

/* Create a symbol name to represent the sources we are annotating.
   Since there can be multiple input files, we choose the main output
   filename (stripped of any path prefixes).  Since filenames can
   contain characters that symbol names do not (eg '-') we have to
   allocate our own name.  */

static bool
init_annobin_output_filesym (void)
{
  char * name;
  unsigned i;

  if (annobin_output_filesym != NULL)
    return true;

  if (annobin_input_filename == NULL)
    {
      if (! init_annobin_input_filename ())
	return false;
    }

  name = (char *) lbasename (annobin_input_filename);

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

  annobin_output_filesym = concat (ANNOBIN_SYMBOL_PREFIX, annobin_extra_prefix, name, NULL);
  annobin_current_endname = concat (annobin_output_filesym, "_end", NULL);
  return true;
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

  if (comment && GET_INT_OPTION_BY_INDEX (OPT_fverbose_asm))
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
		     bool         is_open,
		     annobin_function_info * info)
{
  char buffer1[24];
  char buffer2[128];
  unsigned i;

  if (asm_out_file == NULL)
    return;

  if (annobin_function_verbose
      && ! is_open)
    annobin_inform (INFORM_ALWAYS, "Create function specific note for: %s: %s",
		    info->start_sym, name_description);

  fprintf (asm_out_file, "\t.pushsection %s\n", info->note_section_declaration);

  /* Note we use 4-byte alignment even on 64-bit targets.  This might seem
     wrong for 64-bit systems, but the ELF standard does not specify any
     alignment requirements for notes, and it matches already established
     practice for other types of notes.  Plus it helps reduce the size of
     the notes on 64-bit systems which is a good thing.  */
  fprintf (asm_out_file, "\t.balign 4\n");

  if (name == NULL)
    {
      if (namesz)
	ice ("unable to generate annobin note: null name with non-zero size");

      annobin_emit_asm (".dc.l 0", "no name");
    }
  else if (name_is_string)
    {
      if (strlen ((char *) name) != namesz - 1)
	ice ("unable to generate annobin note: name string does not match name size");

      sprintf (buffer1, ".dc.l %u", namesz);
      sprintf (buffer2 , "namesz [= strlen (%s)]", name);
      annobin_emit_asm (buffer1, buffer2);
    }
  else
    {
      sprintf (buffer1, ".dc.l %u", namesz);
      annobin_emit_asm (buffer1, "size of name");
    }

  if (info->start_sym == NULL)
    {
      if (info->end_sym != NULL)
	ice ("unable to generate annobin note: non-null end_sym with null start_sym");

      annobin_emit_asm (".dc.l 0", "no description");
    }
  else
    {
      if (info->end_sym == NULL)
	{
	  sprintf (buffer1, ".dc.l %u", annobin_is_64bit ? 8 : 4);
	  annobin_emit_asm (buffer1, "descsz [= sizeof (address)]");
	}
      else
	{
	  sprintf (buffer1, ".dc.l %u", annobin_is_64bit ? 16 : 8);
	  annobin_emit_asm (buffer1, "descsz [= 2 * sizeof (address)]");
	}
    }

  sprintf (buffer1, ".dc.l %#x", is_open ? OPEN : FUNC);
  annobin_emit_asm (buffer1, is_open ? "OPEN" : "FUNC");

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

  if (info->start_sym != NULL)
    {
      const char * pointer_decl = annobin_is_64bit ? "\t.quad %s" : "\t.dc.l %s";

      fprintf (asm_out_file, pointer_decl, (char *) info->start_sym);

      if (target_start_sym_bias)
	{
	  /* We know that the annobin_output_filesym symbol has been
	     biased in order to avoid conflicting with the function
	     name symbol for the first function in the file.  So reverse
	     that bias here.  */
	  if (info->start_sym == annobin_output_filesym)
	    fprintf (asm_out_file, "- %d", target_start_sym_bias);
	}

      if (info->end_sym == NULL)
	annobin_emit_asm (NULL, "description [symbol name]");
      else
	{
	  annobin_emit_asm (NULL, "description [symbol names]");

	  fprintf (asm_out_file, pointer_decl, (char *) info->end_sym);
	}

      fprintf (asm_out_file, "\n");
    }

  fprintf (asm_out_file, "\t.popsection\n\n");
  fflush (asm_out_file);

  ++ annobin_note_count;
}

void
annobin_output_bool_note (const char    bool_type,
			  const bool    bool_value,
			  const char *  name_description,
			  bool          is_open,
			  annobin_function_info * info)
{
  char buffer [6];
  unsigned int len;

  len = sprintf (buffer, "GA%c%c", bool_value ? BOOL_T : BOOL_F, bool_type);

  /* Include the NUL byte at the end of the name string.
     This is required by the ELF spec.  */
  annobin_output_note (buffer, len + 1, false /* The name is not ASCII */,
		       name_description, is_open, info);
}

void
annobin_output_string_note (const char    string_type_char,
			    const char *  string,
			    const char *  name_description,
			    bool          is_open,
			    annobin_function_info * info)
{
  unsigned int len = strlen (string) + 5;
  char * buffer;

  buffer = (char *) xmalloc (len);

  sprintf (buffer, "GA%c%c%s", GNU_BUILD_ATTRIBUTE_TYPE_STRING, string_type_char, string);

  /* Be kind to readers of the assembler source, and do
     not put control characters into ascii strings.  */
  annobin_output_note (buffer, len, ISPRINT (string_type_char),
		       name_description, is_open, info);
  free (buffer);
}

void
annobin_output_numeric_note (const char     numeric_type,
			     unsigned long  value,
			     const char *   name_description,
			     bool           is_open,
			     annobin_function_info * info)
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
    ice ("unable to generate annobin note: Numeric value too big to fit into 8 bytes");
  if (value)
    ice ("unable to generate annobin note: Unable to record numeric value");

  annobin_output_note (buffer, i + 1, false, /* The name is not ASCII */
		       name_description, is_open, info);
}

/* Returns the real index into the global_options array of the gcc
   command line option that used to be indexed by CL_OPTION_INDEX.
   
   Returns -1 if the option could not be found.  */

static int
annobin_remap (unsigned int cl_option_index)
{
  if (cl_option_index >= cl_options_count)
    {
      annobin_inform (INFORM_VERBOSE, "Error: attempting to access an unknown gcc command line option");
      annobin_inform (INFORM_VERBOSE, "debug: index = %u max = %u", cl_option_index, cl_options_count);
      return -1;
    }

  /* Sometimes a discrepancy between the gcc used to build annobin
     and the gcc running annobin will mean that an option has moved
     in the cl_options array.  We check here and if necessary adjust
     the index. */
  static struct cl_index_remap
  {
    bool                checked;
    const char *        option_name;
    const unsigned int  original_index;
    unsigned int        real_index;
    union
    {
      int               iflag;
      void *            pflag;
    };
    bool                warned;
  }
  cl_remap [] =
  {
    /* This is an array of the options that we know annobin wants to
       access and for which there are entries in the cl_options array.  */
#define MAKE_ENTRY(opt_name, opt_num, flag_name) \
    { false, opt_name, opt_num, 0, annobin_global_options->x_##flag_name, false}
   
#ifdef flag_stack_clash_protection
    MAKE_ENTRY ("-fstack-clash-protection", OPT_fstack_clash_protection, flag_stack_clash_protection),
#endif
#ifdef flag_cf_protection
    MAKE_ENTRY ("-fcf-protection", OPT_fcf_protection_, flag_cf_protection),
#endif
    MAKE_ENTRY ("-fverbose-asm", OPT_fverbose_asm, flag_verbose_asm),
    MAKE_ENTRY ("-fpic", OPT_fpic, flag_pic),
    MAKE_ENTRY ("-fpie", OPT_fpie, flag_pie),
    MAKE_ENTRY ("-fstack-protector", OPT_fstack_protector, flag_stack_protect),
    MAKE_ENTRY ("-fomit-frame-pointer", OPT_fomit_frame_pointer, flag_omit_frame_pointer),
    MAKE_ENTRY ("-fshort-enums", OPT_fshort_enums, flag_short_enums),
    MAKE_ENTRY ("-fstack-usage", OPT_fstack_usage, flag_stack_usage_info),
    MAKE_ENTRY ("-ffunction-sections", OPT_ffunction_sections, flag_function_sections),
    MAKE_ENTRY ("-freorder-functions", OPT_freorder_functions, flag_reorder_functions),
    MAKE_ENTRY ("-fprofile-values", OPT_fprofile_values, flag_profile_values),
    MAKE_ENTRY ("-finstrument-functions", OPT_finstrument_functions, flag_instrument_function_entry_exit),
    MAKE_ENTRY ("-fprofile", OPT_fprofile, profile_flag),
    MAKE_ENTRY ("-fprofile-arcs", OPT_fprofile_arcs, profile_arc_flag)
  };

  int i;
  for (i = ARRAY_SIZE (cl_remap); --i;)
    {
      if (cl_remap[i].original_index != cl_option_index)
	continue;

      if (cl_remap[i].checked)
	{
	  cl_option_index = cl_remap[i].real_index;
	}
      else if (strncmp (cl_options[cl_option_index].opt_text, cl_remap[i].option_name,
			strlen (cl_remap[i].option_name)) == 0)
	{
	  cl_remap[i].checked = true;
	  cl_remap[i].real_index = cl_remap[i].original_index;
	}
      else
	{
	  /* Search the cl_options array for the option we are expecting.  */
	  unsigned int j;

	  for (j = 0; j < cl_options_count; j++)
	    {
	      if (strncmp (cl_options[j].opt_text, cl_remap[i].option_name,
			   strlen (cl_remap[i].option_name)) == 0)
		{
		  cl_remap[i].checked = true;
		  cl_remap[i].real_index = j;
		  annobin_inform (INFORM_VERBOSE, "had to remap option index %u to %u for option %s",
				  cl_option_index, j, cl_remap[i].option_name);
		  cl_option_index = j;
		  break;
		}
	    }

	  if (j == cl_options_count)
	    {
	      /* The option is no longer in the array!  */
	      annobin_inform (INFORM_VERBOSE, "option %s (index %u) not in cl_options", cl_remap[i].option_name, cl_option_index);
	      cl_remap[i].checked = true;
	      cl_remap[i].real_index = cl_option_index = 0;
	    }
	}
      break;
    }

  if (i < 0)
    {
      /* The option was not recorded in our cl_remap array.
	 This will happen with target specific options.
	 Assume that they have not moved.
	 FIXME: Better would be to have the name passed in.  */
      annobin_inform (INFORM_VERBOSE, "unrecorded gcc option index = %u", cl_option_index);
    }
  else if (cl_option_index == 0)
    return cl_remap[i].iflag;

  void * flag = option_flag_var (cl_option_index, annobin_global_options);

  if (flag == NULL)
    {
      if (! cl_remap[i].warned)
	{
	  annobin_inform (INFORM_VERBOSE, "Error: Could not find option in cl_options, using flag instead");
	  annobin_inform (INFORM_VERBOSE, "debug: index = %u (%s) max = %u",
			  cl_option_index,
			  cl_remap[i].option_name,
			  cl_options_count);
	  cl_remap[i].warned = true;
	}

      /* Try using the flag directly.  */
      return cl_remap[i].iflag;
    }

  return cl_option_index;
}

/* Returns the value of an integer gcc command line option CL_OPTION_INDEX.
   Returns -1 if the option could not be found.  */

int
annobin_get_int_option_by_index (int cl_option_index)
{
  cl_option_index = annobin_remap (cl_option_index);
  if (cl_option_index == -1)
    return -1;

  /* This is just paranoia....  */
  if (cl_option_index >= (int) cl_options_count)
    {
      annobin_inform (INFORM_VERBOSE, "Error: integer gcc command line option index (%d) too big",
		      cl_option_index);
      return -1;
    }

  void * flag = option_flag_var (cl_option_index, annobin_global_options);

  const struct cl_option * option = cl_options + cl_option_index;

  switch (option->var_type)
    {
    case CLVC_EQUAL:
#if GCCPLUGIN_VERSION_MAJOR >= 9
    case CLVC_SIZE:
#endif
    case CLVC_BOOLEAN:
      if (flag == NULL)
	return 0;
      if (option->cl_host_wide_int)
	return * ((HOST_WIDE_INT *) flag);
      else
	return * ((int *) flag);

    case CLVC_ENUM:
      return cl_enums[option->var_enum].get (flag);

    case CLVC_DEFER:
      // FIXME: What to do here ?
      return -1;

    default:
      annobin_inform (INFORM_VERBOSE, "Error: unsupported integer gcc command line option type");
      annobin_inform (INFORM_VERBOSE, "debug: type = %d, index = %d", option->var_type, cl_option_index);
      return -1;
    }
}

/* Returns the value of string format gcc command line option CL_OPTION_INDEX.
   Returns NULL if the option could not be found.  */

const char *
annobin_get_str_option_by_index (int cl_option_index)
{
  cl_option_index = annobin_remap (cl_option_index);
  if (cl_option_index == -1)
    return NULL;

  /* This is just paranoia....  */
  if (cl_option_index >= (int) cl_options_count)
    {
      annobin_inform (INFORM_VERBOSE, "Error: string gcc command line option index (%d) too big",
		      cl_option_index);
      return NULL;
    }

  void * flag = option_flag_var (cl_option_index, annobin_global_options);

  enum cl_var_type var_type = cl_options[cl_option_index].var_type;

  switch (var_type)
    {
    case CLVC_STRING:
      if (flag == NULL)
	return NULL;
      return * (const char **) flag;

    default:
      annobin_inform (INFORM_VERBOSE, "Error: unsupported string gcc command line option type");
      annobin_inform (INFORM_VERBOSE, "debug: type = %d, index = %d", var_type, cl_option_index);
      return NULL;
    }
}

const char *
annobin_get_str_option_by_name (const char * name ATTRIBUTE_UNUSED,
				const char * default_return)
{
#if GCCPLUGIN_VERSION_MAJOR >= 11
  /* GCC version 11 introduced the cl_vars array which provides offsets for
     fields in global_options which are not handled by cl_options.  */
  const struct cl_var * var = cl_vars;

  for (var = cl_vars; var->var_name != NULL; var ++)
    if (strcmp (var->var_name, name) == 0)
      // FIXME: Cache the result ?
      return * (const char **) (((char *) annobin_global_options) + var->var_offset);

  annobin_inform (INFORM_VERBOSE, "WARN: gcc variable '%s' not found within cl_vars array", name);
#endif

  return default_return;
}

const int
annobin_get_int_option_by_name (const char * name ATTRIBUTE_UNUSED,
				const int    default_return)
{
#if GCCPLUGIN_VERSION_MAJOR >= 11
  /* GCC version 11 introduced the cl_vars array which provides offsets for
     fields in global_options which are not handled by cl_options.  */
  const struct cl_var * var = cl_vars;

  for (var = cl_vars; var->var_name != NULL; var ++)
    if (strcmp (var->var_name, name) == 0)
      // FIXME: Cache the result ?
      return * (int *) (((char *) annobin_global_options) + var->var_offset);

  annobin_inform (INFORM_VERBOSE, "WARN: gcc variable '%s' not found within cl_vars array", name);
#endif

  return default_return;
}

static int
compute_pic_option (void)
{
  int val = GET_INT_OPTION_BY_INDEX (OPT_fpie);
  if (val > 1)
    return 4;
  if (val)
    return 3;

  val = GET_INT_OPTION_BY_INDEX (OPT_fpic);
  if (val > 1)
    return 2;
  if (val)
    return 1;
  return 0;
}

static inline int
annobin_get_optimize (void)
{
  return GET_INT_OPTION_BY_NAME (optimize);
}

static inline int
annobin_get_optimize_debug (void)
{
  return GET_INT_OPTION_BY_NAME (optimize_debug);
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
   bit  15     : -Wformat-security
   bit  16     : LTO enabled
   bit  17     : LTO disabled.  */

static unsigned int
compute_GOWall_options (void)
{
  unsigned int val, i;

  /* FIXME: Keep in sync with changes to gcc/flag-types.h:enum debug_info_type.  */
  val = GET_INT_OPTION_BY_NAME (write_symbols);
  if (val > VMS_AND_DWARF2_DEBUG)
    {
      annobin_inform (INFORM_VERBOSE, "unknown debug info type (%d)", val);
      val = 0;
    }

  if (GET_INT_OPTION_BY_NAME (use_gnu_debug_info_extensions))
    val |= (1 << 3);

  i = GET_INT_OPTION_BY_NAME (debug_info_level);
  if (i > DINFO_LEVEL_VERBOSE)
    {
      annobin_inform (INFORM_VERBOSE, "unexpected debug_info_level = %d", i);
    }
  else
    val |= (i << 4);

  i = GET_INT_OPTION_BY_NAME (dwarf_version);
  if (i < 2)
    {
      /* Apparently it is possible for dwarf_version to be -1.  Not sure how
	 this can happen, but handle it anyway.  Since DWARF prior to v2 is
	 deprecated, we use 2 as the version level.  */
      val |= (2 << 6);
      annobin_inform (INFORM_VERBOSE, "dwarf version level %d recorded as 2", i);
    }
  else if (i > 7)
    {
      /* FIXME: We only have 3 bits to record the debug level...  */
      val |= (7 << 6);
      annobin_inform (INFORM_VERBOSE, "dwarf version level %d recorded as 7", i);
    }
  else
    val |= (i << 6);

  i = annobin_get_optimize ();
  if (i > 3)
    val |= (3 << 9);
  else
    val |= (i << 9);

  /* FIXME: It should not be possible to enable more than one of -Os/-Of/-Og,
     so the tests below could be simplified.  */
  if (GET_INT_OPTION_BY_NAME (optimize_size))
    val |= (1 << 11);
  if (GET_INT_OPTION_BY_NAME (optimize_fast))
    val |= (1 << 12);
  if (annobin_get_optimize_debug ())
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
  if (GET_INT_OPTION_BY_NAME (warn_format_security))
    val|= (1 << 15);

  if (in_lto () || GET_STR_OPTION_BY_NAME(flag_lto) != NULL)
    val |= (1 << 16);
  else /* We record the negative so that annocheck can detect that
	  we definitely have recorded something for this feature.  */
    val |= (1 << 17);

  return val;
}

static void
record_GOW_settings (unsigned int gow,
		     bool         is_open,
		     annobin_function_info * info)
{
  char buffer [128];
  unsigned i;

  annobin_inform (INFORM_VERBOSE, "Record status of -g (%d), -O (%d), -Wall (%s) and LTO (%s) for %s",
		  (gow >> 4) & 3,
		  (gow >> 9) & 3,
		  gow & (3 << 14) ? "enabled" : "disabled",
		  gow & (1 << 16) ? "enabled" : "not enabled",
		  is_open ? "<global>" : info->func_name);
  
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

  annobin_output_note (buffer, i + 1, false, /* The name is not ASCII.  */
		       "numeric: -g/-O/-Wall", is_open, info);
}

static void
record_stack_protector_note (bool is_global, annobin_function_info * info)
{
  int optval = GET_INT_OPTION_BY_INDEX (OPT_fstack_protector);

  if (optval < 1 && is_global && in_lto ())
    {
      /* The LTO compiler determines stack protector enablement on a per-function
	 basis unless enabled globally.  So do not record a negative global setting.

	 FIXME: We should check the option's flags to make sure that CL_OPTIMIZATION
	 is set.  */
      annobin_inform (INFORM_VERBOSE, "Not recording unset global stack protector setting when in LTO mode");
      return;
    }
  /* See BZ 1563141 for an example where global_stack_protection can be -1.  */
  else if (optval == -1)
    {
      annobin_inform (INFORM_VERBOSE, "Not recording stack protector value of -1");
      return;
    }

  const char * setting;
  switch (optval)
    {
    case 0: setting = "none"; break;
    case 1: setting = "basic"; break;
    case 4: setting = "explicit"; break;
    case 2: setting = "all"; break;
    case 3: setting = "strong"; break;
    default: setting = "unknown"; break;
    }

  if (is_global)
    annobin_inform (INFORM_VERBOSE, "Recording global stack protector setting of '%s'", setting);
  else
    annobin_inform (INFORM_VERBOSE, "Recording local stack protector setting of '%s' for %s",
		    setting, info->func_name);

  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_STACK_PROT, optval,
			     "numeric: -fstack-protector status",
			     is_global, info);
}

#ifdef flag_stack_clash_protection
static void
record_stack_clash_note (bool is_global, annobin_function_info * info)
{
  int  optval = GET_INT_OPTION_BY_INDEX (OPT_fstack_clash_protection);

  if (optval == 0 && is_global && in_lto ())
    {
      /* The LTO compiler determines stack_clash_protection on a per-function basis
	 unless enabled globally.  So do not record a negative global setting.

	 FIXME: We should check the option's flags to make sure that CL_OPTIMIZATION
	 is set.  */
      annobin_inform (INFORM_VERBOSE, "Not recording unset global stack clash protection setting when in LTO mode");
      return;
    }
  else if (is_global)
    annobin_inform (INFORM_VERBOSE, "Recording global stack clash protection setting of '%s'",
		    optval ? "enabled" : "disabled");
  else
    annobin_inform (INFORM_VERBOSE, "Recording local stack clash protection status of '%s' for %s",
		    optval ? "enabled" : "disabled", info->func_name);

  char buffer [128];
  unsigned len = sprintf (buffer, "GA%cstack_clash", optval ? BOOL_T : BOOL_F);
  
  annobin_output_note (buffer, len + 1, true, /* The name is ASCII.  */
		       "bool: -fstack-clash-protection status", is_global, info);
}
#endif

#ifdef flag_cf_protection
static void
record_cf_protection_note (bool is_global, annobin_function_info * info)
{
  int optval = GET_INT_OPTION_BY_INDEX (OPT_fcf_protection_);

  if (optval == 0 && is_global && in_lto ())
    {
      /* The LTO compiler determines cf_protection on a per-function basis
	 unless enabled globally.  So do not record a negative global setting.

	 FIXME: We should check the option's flags to make sure that CL_TARGET
	 is set.  */
      annobin_inform (INFORM_VERBOSE, "Not recording unset global cf_protection setting when in LTO mode");
      return;
    }

  const char * setting;
  switch (optval)
    {
    case CF_NONE:
    case CF_NONE | CF_SET:
      setting = "none";
      break;
      
    case CF_RETURN:
    case CF_RETURN | CF_SET:
      setting = "return only";
      break;
      
    case CF_BRANCH:
    case CF_BRANCH | CF_SET:
      setting = "branch only";
      break;
      
    case CF_FULL:
    case CF_FULL | CF_SET:
      setting = "full";
      break;

    default:
      setting = "unknown";
      break;
    }

  if (is_global)
    annobin_inform (INFORM_VERBOSE, "Recording global cf_protection setting of '%s'", setting);
  else
    annobin_inform (INFORM_VERBOSE, "Recording local cf_protection status of '%s' for %s",
		    setting, info->func_name);
  
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%ccf_protection", NUMERIC);

  /* We bias the cf_protection enum value by 1 so that we do not get confused by a zero value.  */
  buffer[++len] = optval + 1;
  buffer[++len] = 0;

  annobin_output_note (buffer, len + 1, false, /* The name is not ASCII.  */
		       "numeric: -fcf-protection status", is_global, info);
}
#endif

static void
record_frame_pointer_note (bool is_open, annobin_function_info * info)
{
  char buffer [128];
  unsigned len;
  int val = GET_INT_OPTION_BY_INDEX (OPT_fomit_frame_pointer);

  len = sprintf (buffer, "GA%comit_frame_pointer", val ? BOOL_T : BOOL_F);

  annobin_inform (INFORM_VERBOSE, "Record omit-frame-pointer status of %d", val);
  annobin_output_note (buffer, len + 1, true, /* The name is ASCII.  */
		       "bool: -fomit-frame-pointer status", is_open, info);
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
record_fortify_level (int level, bool is_open, annobin_function_info * info)
{
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%cFORTIFY", NUMERIC);

  buffer[++len] = level;
  buffer[++len] = 0;
  annobin_output_note (buffer, len + 1, false /* Name is not ASCII.  */,
		       "_FORTIFY SOURCE level", is_open, info);
  annobin_inform (INFORM_VERBOSE, "Record _FORTIFY SOURCE level of %d", level);
}

static void
record_glibcxx_assertions (signed int on, bool is_open, annobin_function_info * info)
{
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%cGLIBCXX_ASSERTIONS", on > 0 ? BOOL_T : BOOL_F);

  annobin_output_note (buffer, len + 1, false /* Name is not ASCII.  */,
		       on > 0 ? "_GLIBCXX_ASSERTIONS defined"
		       : on < 0 ? "_GLIBCXX_ASSERTIONS not seen"
		       : "_GLIBCXX_ASSERTIONS not defined",
		       is_open, info);
  annobin_inform (INFORM_VERBOSE, "Record _GLIBCXX_ASSERTIONS as %s", on > 0 ? "defined" : "not defined");
}

static annobin_function_info current_func;

static void
clear_current_func (void)
{
  free ((void *) current_func.func_name);
  free ((void *) current_func.asm_name);
  free ((void *) current_func.section_name);
  free ((void *) current_func.group_name);
  free ((void *) current_func.note_section_declaration);
  free ((void *) current_func.start_sym);
  free ((void *) current_func.end_sym);
  free ((void *) current_func.unlikely_section_name);
  free ((void *) current_func.unlikely_end_sym);

  memset (& current_func, 0, sizeof current_func);
}

static void
annobin_emit_function_notes (bool force)
{
  /* Make a copy of the current function info, so that we can override the symbols.  */
  annobin_function_info local_info = current_func;
  
  annobin_target_specific_function_notes (& local_info, force);

  int current_val;

  current_val = GET_INT_OPTION_BY_INDEX (OPT_fstack_protector);
  if (force || global_stack_prot_option != current_val)
    {
      record_stack_protector_note (false /* local */, & local_info);
      /* We no longer need to include the symbols in the notes we generate.  */
      local_info.start_sym = local_info.end_sym = NULL;
    }

#ifdef flag_stack_clash_protection
  current_val = GET_INT_OPTION_BY_INDEX (OPT_fstack_clash_protection);
  if (force || global_stack_clash_option != current_val)
    {
      record_stack_clash_note (false /* not global */, & local_info);
      local_info.start_sym = local_info.end_sym = NULL;
    }
#endif

#ifdef flag_cf_protection
  current_val = GET_INT_OPTION_BY_INDEX (OPT_fcf_protection_);
  if (force || global_cf_option != current_val)
    {
      record_cf_protection_note (false /* local */, & local_info);
      local_info.start_sym = local_info.end_sym = NULL;
    }
#endif

  current_val = GET_INT_OPTION_BY_INDEX (OPT_fomit_frame_pointer);
  if (force || global_omit_frame_pointer != current_val)
    {
      annobin_inform (INFORM_VERBOSE, "Recording omit_frame_pointer status of %d for %s",
		      current_val, local_info.func_name);

      record_frame_pointer_note (false /* not OPEN.  */, & local_info);
      local_info.start_sym = local_info.end_sym = NULL;
    }

  current_val = compute_pic_option ();
  if (force || global_pic_option != current_val)
    {
      annobin_inform (INFORM_VERBOSE, "Recording PIC status of %s", local_info.func_name);
      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_PIC, current_val,
				   "numeric: pic type", false /* not OPEN.  */, & local_info);
      local_info.start_sym = local_info.end_sym = NULL;
    }

  current_val = compute_GOWall_options ();
  if (force || global_GOWall_options != (unsigned) current_val)
    {
      annobin_inform (INFORM_VERBOSE, "Recording debug/optimize/warning value of %x for %s",
		      current_val, local_info.func_name);
      record_GOW_settings (current_val, false /* This is a FUNC note.  */, & local_info);
      local_info.start_sym = local_info.end_sym = NULL;
    }

  current_val = GET_INT_OPTION_BY_INDEX (OPT_fshort_enums);
  if (current_val != -1
      && (force || global_short_enums != current_val))
    {
      annobin_inform (INFORM_VERBOSE, "Recording short enums in use in %s", local_info.func_name);
      annobin_output_bool_note (GNU_BUILD_ATTRIBUTE_SHORT_ENUM, current_val,
				current_val ? "bool: short-enums: on" : "bool: short-enums: off",
				false /* not OPEN.  */, & local_info);
      local_info.start_sym = local_info.end_sym = NULL;
    }

  current_val = GET_INT_OPTION_BY_INDEX (OPT_fstack_usage);
  if (annobin_enable_stack_size_notes && current_val)
    {
      if ((unsigned long) current_function_static_stack_size > stack_threshold)
	{
	  annobin_inform (INFORM_VERBOSE, "Recording stack usage of %lu for %s",
			  (unsigned long) current_function_static_stack_size,
			  local_info.func_name);

	  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_STACK_SIZE,
				       current_function_static_stack_size,
				       "numeric: stack-size",
				       false /* not OPEN.  */,
				       & local_info);
	  local_info.start_sym = local_info.end_sym = NULL;
	}

      annobin_total_static_stack_usage += current_function_static_stack_size;

      if ((unsigned long) current_function_static_stack_size > annobin_max_stack_size)
	annobin_max_stack_size = current_function_static_stack_size;
    }

  /* Always record the fortify and assertion levels as we cannot be
     sure that the global values have been recorded.  cf BZ 1703500.  */
  record_fortify_level (global_fortify_level, false /* not OPEN.  */,
			& local_info);
  record_glibcxx_assertions (global_glibcxx_assertions, false /* Not OPEN.  */, & local_info);
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
  annobin_inform (INFORM_VERBOSE, "Create symbol %s", name);
}

/* Create any notes specific to the current function.  */

static void
annobin_create_function_notes (void * gcc_data, void * user_data)
{
  unsigned int  count;
  bool          force;

  if (current_func.func_name != NULL)
    ice ("new function encountered whilst still processing old function");

  current_func.func_name = current_function_name ();
  current_func.asm_name  = function_asm_name ();

  if (asm_out_file == NULL)
    {
      annobin_inform (INFORM_VERBOSE, "Output file not available - unable to generate notes for %s",
		      current_func.func_name);
      return;
    }
  
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

  else if (GET_INT_OPTION_BY_INDEX (OPT_ffunction_sections))
    {
      /* Special case: at -O2 or higher special functions get a prefix added.  */
      if (GET_INT_OPTION_BY_INDEX (OPT_freorder_functions))
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

  else if (GET_INT_OPTION_BY_INDEX (OPT_freorder_functions) /* && targetm_common.have_named_sections */)
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
	  if (! in_lto () && ! GET_INT_OPTION_BY_INDEX (OPT_fprofile_values))
	    current_func.section_name = concat (STARTUP_SECTION, NULL);
	}
      else if (exit)
	{
	  current_func.section_name = concat (EXIT_SECTION, NULL);
	}
      else if (likely)
	{
	  /* FIXME: Never seen this one, either.  */
	  if (! in_lto () && ! GET_INT_OPTION_BY_INDEX (OPT_fprofile_values))
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
	{
	  current_func.group_name = concat (IDENTIFIER_POINTER (DECL_COMDAT_GROUP (current_function_decl)), NULL);

	  /* Include a group name in our attribute section name.  */
	  current_func.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME, current_func.section_name,
							  ", \"G\", %note, ",
							  current_func.group_name,
							  ", comdat",
							  NULL);
	}
      /* Check for linkonce sections.  These cannot be put into a group as it breaks the
	 linkonce semantics.  Plus we have to put the notes into linkonce sections as well.  */
      else if (strncmp (current_func.section_name, LINKONCE_SEC_PREFIX,
		       strlen (LINKONCE_SEC_PREFIX)) == 0)
	{
	  current_func.group_name = NULL;
	  current_func.note_section_declaration = concat (LINKONCE_SEC_PREFIX,
							  GNU_BUILD_ATTRS_SECTION_NAME,
							  current_func.section_name,
							  ", \"\", %note", NULL);
	}
      else if (annobin_attach_type == group)
	{
	  current_func.group_name = concat (current_func.section_name, ANNOBIN_GROUP_NAME, NULL);
	  /* Include a group name in our attribute section name.  */
	  current_func.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME, current_func.section_name,
							  ", \"G\", %note, ",
							  current_func.group_name,
							  NULL);
	}
      else if (annobin_attach_type == link_order)
	{
	  current_func.group_name = NULL;
	  current_func.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME, current_func.section_name,
							  ", \"o\", %note, ",
							  current_func.section_name,
							  NULL);
	}
      else /* assume annobin_attach_type == none  */
	{
	  current_func.group_name = NULL;
	  current_func.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME, current_func.section_name,
							  ", \"\", %note", NULL);
	}
    }
 else
   {
     if (current_func.comdat)
       ice ("current function is comdat but has no function section");

     if (current_func.note_section_declaration == NULL)
       {
	 switch (annobin_attach_type)
	   {
	   default:
	   case none:
	     current_func.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME, 
							     ", \"\", %note",
							     NULL);
	     break;
	   case group:
	     current_func.group_name = concat (CODE_SECTION, ANNOBIN_GROUP_NAME, NULL);
	     current_func.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME,
						     ", \"G\", %note, ",
						     current_func.group_name,
						     NULL);
	     break;
	   case link_order:
	     current_func.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME,
							     ", \"o\", %note, "
							     CODE_SECTION,	
							     NULL);
	     break;
	   }
       }
   }

  /* We use our own function start and end symbols so that they will
     not interfere with the program proper.  In particular if we use
     the function name symbol ourselves then we can cause problems
     when the linker attempts to resolve relocs against it and finds
     that it has both PC relative and absolute relocs.

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

      /* If there is a possibility that GCC might generate a cold section
	 variant of the current function section, then we need to annotate
	 that as well.  */

      current_func.start_sym = concat (ANNOBIN_SYMBOL_PREFIX, current_func.asm_name, ".start", COLD_SECTION, NULL);
      current_func.unlikely_end_sym = concat (ANNOBIN_SYMBOL_PREFIX, current_func.asm_name, ".end", COLD_SECTION, NULL);

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

  annobin_inform (INFORM_VERBOSE, "queue an attachment for section %s to group %s", section_name, group_name);
  item->section_name = concat (section_name, NULL);
  item->group_name = concat (group_name, NULL);
  item->next = attach_list;
  attach_list = item;
}

static void
emit_queued_attachments (void)
{
  if (annobin_attach_type != group)
    return;

  attach_item * item;
  attach_item * next = NULL;
  for (item = attach_list; item != NULL; item = next)
    {
      const char * name = item->section_name;

      if (item->group_name != NULL && item->group_name[0] != 0)
	{
	  fprintf (asm_out_file, "\t.pushsection %s\n", name);
	  fprintf (asm_out_file, "\t.attach_to_group %s", item->group_name);
	  if (GET_INT_OPTION_BY_INDEX (OPT_fverbose_asm))
	    fprintf (asm_out_file, " %s Add the %s section to the %s group",
		     ASM_COMMENT_START, name, item->group_name);
	  fprintf (asm_out_file, "\n");
	  fprintf (asm_out_file, "\t.popsection\n");
	}
      else
	ice ("queued attachment to an empty group");

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
  // attach_list = NULL;
}

static void
annobin_create_function_end_symbol (void * gcc_data, void * user_data)
{
  if (asm_out_file == NULL)
    {
      annobin_inform (INFORM_VERBOSE, "unable to create function end symbols.");
      return;
    }

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
	     Note - we attempt to create a new section that will be appended to
	     the end of the sections that are going into the section group.  */
	  fprintf (asm_out_file, "\t.pushsection %s.zzz, \"ax\", %%progbits\n",
		   current_func.unlikely_section_name);
	  annobin_emit_symbol (current_func.unlikely_end_sym);
	  fprintf (asm_out_file, "\t.popsection\n");

	  /* Make sure that the unlikely section will be added into the
	     current function's group.  */
	  queue_attachment (current_func.unlikely_section_name,
			    current_func.group_name);
	}

      fprintf (asm_out_file, "\t.pushsection %s\n", current_func.section_name);

      if (annobin_attach_type == group)
	{
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
	     for garbage collected function sections will not be discarded by
	     the linker.

	     Note - we do not have to do this for COMDAT sections as they are
	     already part of a section group, and gcc always includes the group
	     name in its .section directives.

	     Note - we do not emit these attach directives here as function
	     sections can be reused.  So instead we accumulate them and issue
	     them all at the end of compilation.  */
	  queue_attachment (current_func.section_name, current_func.group_name);
	}
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
      if (annobin_attach_type == group)
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
    fprintf (asm_out_file, "\t.pushsection %s, \"ax\", %%progbits\n",
	     CODE_SECTION);

  fprintf (asm_out_file, "\t%s %s%s\n", global_file_name_symbols ? ".global" : ".hidden",
	   annobin_output_filesym, suffix);

  /* Note - we used to set the type of the symbol to STT_OBJECT, but that is
     incorrect because that type is for:
       "A data object, such as a variable, an array, and so on".

     There is no ELF symbol to represent a compilation unit, (STT_FILE only
     covers a single source file and has special sematic requirements), so
     instead we use STT_NOTYPE.  (Ideally we could use STT_LOOS+n, but there
     is a problem with the GAS assembler, which does not allow such values to
     be set on symbols).  */
  fprintf (asm_out_file, "\t.type %s%s, STT_NOTYPE\n", annobin_output_filesym, suffix);

  if (target_start_sym_bias)
    {
      /* We set the address of the start symbol to be the current address plus
	 a bias value.  That way this symbol will not be confused for a file
	 start/function start symbol.

	 There is special code in annobin_output_note() that undoes this bias
	 when the symbol's address is being used to compute a range for the
	 notes.  */
      fprintf (asm_out_file, "\t.set %s%s, . + %d\n", annobin_output_filesym, suffix, target_start_sym_bias);

      /* FIXME: A workaround for BZ 1880634.
	 Ensure that we do not have empty special text sections so that the
	 annobin start symbols are never beyond the end of the sections.  */
      if (* suffix && enable_ppc64_nops)
	annobin_emit_asm (".nop", "Inserted by the annobin plugin.  Disable with -fplugin-arg-annobin-no-ppc64-nops");
    }
  else
    fprintf (asm_out_file, "\t.equiv %s%s, .\n", annobin_output_filesym, suffix);

  /* We explicitly set the size of the symbol to 0 so that it will not
     confuse other tools (eg GDB, elfutils) which look for symbols that
     cover an address range.  */
  fprintf (asm_out_file, "\t.size %s%s, 0\n", annobin_output_filesym, suffix);

  fprintf (asm_out_file, "\t.popsection\n");

  annobin_function_info info;
  memset (& info, 0, sizeof info);
  info.start_sym = concat (annobin_output_filesym, suffix, NULL);
  info.end_sym  = concat (annobin_current_endname, suffix, NULL);

  switch (annobin_attach_type)
    {
    default:
    case none:
      info.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME, 
					      ", \"\", %note",
					      NULL);
      break;
    case group:
      info.group_name = concat (CODE_SECTION, suffix, ANNOBIN_GROUP_NAME, NULL);
      info.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME,
					      * suffix ? suffix : "",
					      ", \"G\", %note, ",
					      info.group_name,
					      NULL);
      break;
    case link_order:
      info.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME,
					      * suffix ? suffix : "",
					      ", \"o\", %note, "
					      CODE_SECTION,	
					      suffix,
					      NULL);
      break;
    }

  char buffer [124];

  sprintf (buffer, "%d%c%d", SPEC_VERSION, producer_char, annobin_version);
  annobin_output_string_note (GNU_BUILD_ATTRIBUTE_VERSION, buffer,
			      "string: protocol version", true /* Is OPEN.  */,
			      & info);

  free ((void *) info.group_name);
  free ((void *) info.note_section_declaration);
  free ((void *) info.end_sym);
  free ((void *) info.start_sym);
}

static void
emit_global_notes (const char * suffix)
{
  annobin_function_info info;
  memset (& info, 0, sizeof info);

  switch (annobin_attach_type)
    {
    default:
    case none:
      info.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME, 
					      ", \"\", %note",
					      NULL);
      break;
    case group:
      info.group_name = concat (CODE_SECTION, suffix, ANNOBIN_GROUP_NAME, NULL);
      info.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME,
					      * suffix ? suffix : "",
					      ", \"G\", %note, ",
					      info.group_name,
					      NULL);
      break;
    case link_order:
      info.note_section_declaration = concat (GNU_BUILD_ATTRS_SECTION_NAME,
					      * suffix ? suffix : "",
					      ", \"o\", %note, "
					      CODE_SECTION,	
					      suffix,
					      NULL);
      break;
    }

  annobin_inform (INFORM_VERBOSE, "Emit global notes for section %s%s",
		  CODE_SECTION, suffix);

  /* Record the versions of the compiler.  */
  annobin_output_string_note (GNU_BUILD_ATTRIBUTE_TOOL, run_version,
			      "string: build-tool", true /* An OPEN note.  */,
			      & info);
  annobin_output_string_note (GNU_BUILD_ATTRIBUTE_TOOL, build_version,
			      "string: build-tool", true /* An OPEN note.  */,
			      & info);
  annobin_output_string_note (GNU_BUILD_ATTRIBUTE_TOOL,
			      concat ("plugin name: ", plugin_name, NULL),
			      "string: build-tool", true /* An OPEN note.  */,
			      & info);

  /* Record optimization level, -W setting and -g setting  */
  record_GOW_settings (global_GOWall_options, true /* This is an OPEN note.  */,
		       & info);

  /* Record -fstack-protector option.  */
  record_stack_protector_note (true /* global */, & info);

#ifdef flag_stack_clash_protection
  /* Record -fstack-clash-protection option.  */
  record_stack_clash_note (true /* global */, & info);
#endif

#ifdef flag_cf_protection
  /* Record -fcf-protection option.  */
  record_cf_protection_note (true /* global */, & info);
#endif

  record_fortify_level (global_fortify_level, true /* An OPEN note.  */, & info);
  record_glibcxx_assertions (global_glibcxx_assertions, true /* An OPEN note.  */, & info);

  /* Record the PIC status.  */
  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_PIC, global_pic_option,
			       "numeric: PIC", true /* An OPEN note.  */, & info);
  annobin_inform (INFORM_VERBOSE, "Record global PIC setting of %d", global_pic_option);

  /* Record enum size.  */
  annobin_output_bool_note (GNU_BUILD_ATTRIBUTE_SHORT_ENUM, global_short_enums != 0,
			    global_short_enums != 0 ? "bool: short-enums: on" : "bool: short-enums: off",
			    true /* An OPEN note.  */, & info);
  annobin_inform (INFORM_VERBOSE, "Record global SHORT ENUM setting of %d", global_short_enums);

  record_frame_pointer_note (true /* An OPEN note.  */, & info);

  /* Building code with profiling, instrumentation or sanitization enabled
     can slow it down.  (cf PR 1753918).  Whilst this may be desireable
     during development it is probably a bad idea when creating production
     binaries.  So emit a note that can be detected and reported by annocheck.

     NB/ Since this is not a security feature we do not emit a note if none
     of these options are enabled.  This helps to minimize the size of the
     annobin data.

     FIXME: At the moment we do not check to see if any of these flags change
     on a per-function basis.  */
  if (GET_INT_OPTION_BY_INDEX (OPT_finstrument_functions)
#ifdef flag_sanitize
      || GET_INT_OPTION_BY_NAME (flag_sanitize)
#endif
      || GET_INT_OPTION_BY_INDEX (OPT_fprofile)
      || GET_INT_OPTION_BY_INDEX (OPT_fprofile_arcs))
    {
      char buffer[128];
      unsigned int len = sprintf (buffer, "GA%cINSTRUMENT:%u/%u/%u/%u",
				  GNU_BUILD_ATTRIBUTE_TYPE_STRING,
#ifdef flag_sanitize
				  GET_INT_OPTION_BY_NAME (flag_sanitize) ? 1 : 0,
#else
				  0,
#endif
				  GET_INT_OPTION_BY_INDEX (OPT_finstrument_functions),
				  GET_INT_OPTION_BY_INDEX (OPT_fprofile),
				  GET_INT_OPTION_BY_INDEX (OPT_fprofile_arcs));
      annobin_inform (INFORM_VERBOSE,
		      "Instrumentation options enabled: sanitize: %u, function entry/exit: %u, profiling: %u, profile arcs: %u",
#ifdef flag_sanitize
		      GET_INT_OPTION_BY_NAME (flag_sanitize) ? 1 : 0,
#else
		      0,
#endif
		      GET_INT_OPTION_BY_INDEX (OPT_finstrument_functions),
		      GET_INT_OPTION_BY_INDEX (OPT_fprofile),
		      GET_INT_OPTION_BY_INDEX (OPT_fprofile_arcs));

      annobin_output_note (buffer, len + 1, true /* The name is ASCII.  */,
			   "string: details of profiling enablement",
			   true /* An OPEN note.  */, & info);
    }

  /* Record target specific notes.  */
  annobin_record_global_target_notes (& info);

  free ((void *) info.group_name);
  free ((void *) info.note_section_declaration);
}

#define FORTIFY_OPTION "_FORTIFY_SOURCE"
#define GLIBCXX_OPTION "_GLIBCXX_ASSERTIONS"

static void
annobin_record_define (const char * arg)
{
  if (arg == NULL)
    return;

  annobin_inform (INFORM_VERY_VERBOSE, "decoded arg -D%s", arg);

  if (strncmp (arg, FORTIFY_OPTION, strlen (FORTIFY_OPTION)) == 0)
    {
      int level = atoi (arg + strlen (FORTIFY_OPTION) + 1);

      if (level < 0 || level > 3)
	{
	  annobin_inform (INFORM_ALWAYS, "Unexpected value in -D" FORTIFY_OPTION "%s", arg);
	  level = 0;
	}

      if (global_fortify_level == -1)
	global_fortify_level = level;
    }

  else if (strncmp (arg, GLIBCXX_OPTION, strlen (GLIBCXX_OPTION)) == 0)
    {
      if (global_glibcxx_assertions == -1)
	global_glibcxx_assertions = true;
    }
}

static void
annobin_record_undefine (const char * arg)
{
  if (arg == NULL)
    return;

  annobin_inform (INFORM_VERY_VERBOSE, "decoded arg -U%s", arg);

  if (strncmp (arg, FORTIFY_OPTION, strlen (FORTIFY_OPTION)) == 0)
    {
      if (global_fortify_level == -1)
	global_fortify_level = 0;
    }
  else if (strncmp (arg, GLIBCXX_OPTION, strlen (GLIBCXX_OPTION)) == 0)
    {
      if (global_glibcxx_assertions == -1)
	global_glibcxx_assertions = false;
    }
}

/* Returns true if STRING ends with TERMINATOR.  */

static bool
ends_with (const char * string, const char * terminator)
{
  if (string == NULL || terminator == NULL)
    return false;

  size_t tlen = strlen (terminator);
  size_t slen = strlen (string);

  if (tlen > slen)
    return false;

  string += slen - tlen;
  return strcmp (string, terminator) == 0;
}

static void
annobin_active_check (const char * message)
{
  // FIXME - for some reason the prototype of warning() in diagnostic-core.h
  // does not match the implementation.  So we use our own prototype here.
  extern bool warning (int, const char *, ...);

  if (annobin_active_checks == 1)
    // FIXME: We should find an OPT_ value to use here so
    // that users can disable these warnings if they need to.
    warning (0, "%s", message);
  else if (annobin_active_checks == 2)
    error ("%s", message);
}

static void
annobin_create_global_notes (void * gcc_data, void * user_data)
{
  if (asm_out_file == NULL)
    {
      /* This happens during LTO compilation.  Compilation is triggered
	 before any output file has been opened.  Since we do not have
	 the file handle we cannot emit any notes.  If we are lucky however
	 the recompilation process will be repeated later on with a real
	 output file and so the notes can be generated then.

	 FIXME: This does not always happen however and we can end up
	 with LTO output containing no notes.  We need to find some way
	 to inject notes into an LTO generated meta-object file...  */
      annobin_inform (INFORM_VERBOSE, "Output file not available - unable to generate global notes");
      return;
    }

  /* Record global information.
     Note - we do this here, rather than in plugin_init() as some
     information, eg PIC status and POINTER_SIZE, may not be initialised
     until after the target backend has had a chance to process its
     command line options, and this happens *after* plugin_init.  */

  /* Compute the default data size.  */
  unsigned psize = annobin_get_target_pointer_size ();
  annobin_inform (INFORM_VERBOSE, "Target's pointer size: %u bits", psize);
  switch (psize)
    {
    case 16:
    case 32:
      annobin_is_64bit = false; break;
    case 64:
      annobin_is_64bit = true; break;
    default:
      ice ("Illegal target pointer size");
      return;
    }

  if (annobin_enable_stack_size_notes)
    /* We must set this flag in order to obtain per-function stack usage info.  */
    annobin_global_options->x_flag_stack_usage_info = 1;

#ifdef flag_stack_clash_protection
  global_stack_clash_option = GET_INT_OPTION_BY_INDEX (OPT_fstack_clash_protection);
  /* The LTO compiler determines stack_clash_protection on a per-function basis
     unless enabled globally.  So do not record a negative global setting.  */
  if (global_stack_clash_option == 0 && in_lto ())
    global_stack_clash_option = -1;
#endif

#ifdef flag_cf_protection
  global_cf_option = GET_INT_OPTION_BY_INDEX (OPT_fcf_protection_);
  /* The LTO compiler determines cf_protection on a per-function basis
     unless enabled globally.  So do not record a negative global setting.  */
  if (global_cf_option == 0 && in_lto ())
    global_cf_option = -1;
#if 0
  else if ((global_cf_option & CF_FULL) == 0)
    annobin_active_check error ("-fcf-protection=full needed");
#endif
#endif

  global_stack_prot_option = GET_INT_OPTION_BY_INDEX (OPT_fstack_protector);
  /* The LTO compiler determines stack_protector on a per-function basis
     unless enabled globally.  So do not record a negative global setting.  */
  if (global_stack_prot_option == 0 && in_lto ())
    global_stack_prot_option = -1;
  
  global_pic_option = compute_pic_option ();
  global_short_enums = GET_INT_OPTION_BY_INDEX (OPT_fshort_enums);
  global_GOWall_options = compute_GOWall_options ();
  global_omit_frame_pointer = GET_INT_OPTION_BY_INDEX (OPT_fomit_frame_pointer);

#if 0
  if (annobin_get_optimize () < 2
      && ! annobin_get_optimize_debug ())
    annobin_active_check ("optimization level is too low!");
#endif
  
  /* Look for -D _FORTIFY_SOURCE=<n> and -D_GLIBCXX_ASSERTIONS on the
     original gcc command line.  Scan backwards so that we record the
     last version of the option, should multiple versions be set.  */

  int i;

  annobin_inform (INFORM_VERY_VERBOSE, "There are %d options in the saved_decoded_options array",
		  save_decoded_options_count);

  for (i = save_decoded_options_count; i--;)
    {
      const char * arg = save_decoded_options[i].arg;

      annobin_inform (INFORM_VERY_VERBOSE, "Examining saved option: %ld %s",
		      (long) save_decoded_options[i].opt_index, arg ? arg : "<none>");
      switch (save_decoded_options[i].opt_index)
	{
	case OPT_Wp_:
	  /* Note - not sure if this option will ever appear here,
	     but there is no harm in supporting it.  */
	  if (arg != NULL)
	    {
	      switch (arg[0])
		{
		case 'D':
		  annobin_record_define (arg + 1);
		  break;
		case 'U':
		  annobin_record_undefine (arg + 1);
		  break;
		default:
		  break;
		}
	    }
	  break;
	case OPT_U:
	  annobin_record_undefine (arg);
	  break;
	case OPT_D:
	  annobin_record_define (arg);
	  break;
	default:
	  break;
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

  if (global_fortify_level == -1)
    {
      if (in_lto ())
	{
	  /* In LTO mode the preprocessed options are not passed on.
	     Siganl this to annocheck so that it can decide what to do.  */
	  global_fortify_level = -2;
	  annobin_inform (INFORM_VERBOSE, "Setting -D_FORTIFY_SOURCE to unknown-because-of-LTO");
	}
      /* BZ 1862718: We have no reliable way to determine if the input file
	 was preprocessed before being passed to gcc.  Plus we do not have
	 access to the original input text, we cannot examine that.  So for
	 now we assume that if the input filename ends in .i or .ii then
	 it is preprocessed.
	 
	 Since preprocessed inputs ignore any -D, -U or -Wp options on
	 the command line, we just have to assume that they were created
	 with the necessry defines enabled.  */
      else if (ends_with (annobin_input_filename, ".i")
	       || ends_with (annobin_input_filename, ".ii"))
	{
	  annobin_inform (INFORM_VERY_VERBOSE, "Assuming -D_FORTIFY_SOURCE=2 for preprocessed input");
	  global_fortify_level = 2;
	}      
    }

  /* A simplified version of the above if() statement, but for GLIBCXX_ASSERTIONS.  */
  if (global_glibcxx_assertions == -1
      && (in_lto ()
	  || ends_with (annobin_input_filename, ".i")
	  || ends_with (annobin_input_filename, ".ii")))
    {
      global_glibcxx_assertions = 1;
      annobin_inform (INFORM_VERY_VERBOSE, "Assuming -D_GLIBCXX_ASSERTIONS for LTO/preprocessed input");
    }
  
  if (! in_lto ()
      && GET_STR_OPTION_BY_NAME(flag_lto) != NULL)
    {
      bool warned = false;

      /* Because of the hack above, if we know that we are generating a lto
	 object file and the preprocessor values are insufficient, then we
	 generate a warning message for the user.  We do not do this for all
	 input however as there is no way for a plugin to distinguish between
	 preprocessed input and non-preprocessed input.*/
      if (global_fortify_level < 2)
	{
	  if (global_fortify_level == -1)
	    annobin_active_check ("-D_FORTIFY_SOURCE not defined");
	  else
	    annobin_active_check ("-D_FORTIFY_SOURCE defined but value is too low");
	  warned = true;
	}

      if (global_glibcxx_assertions != 1)
	{
	  if (ends_with (annobin_input_filename, ".c")
	      || ends_with (annobin_input_filename, ".i"))
	    {
	      global_glibcxx_assertions = 1;
	      annobin_inform (INFORM_VERY_VERBOSE, "Ignoring lack of -D_GLIBCXX_ASSERTIONS for LTO processing of C source file");
	    }
	  else
	    {
	      annobin_inform (INFORM_ALWAYS, _("Warning: -D_GLIBCXX_ASSERTIONS not defined"));
	      warned = true;
	    }
	}

      if (warned)
	annobin_inform (INFORM_VERBOSE, _("This warning is being issued now because LTO is enabled, and LTO compilation does not use preprocessor options"));
    }

  /* It is possible that no code will end up in the .text section.
     Eg because the compilation was run with the -ffunction-sections option.
     Nevertheless we generate this symbol in the .text section
     as at this point we cannot know which section(s) will be used
     by compiled code.  */
  char producer_char = in_lto () ? ANNOBIN_TOOL_ID_GCC_LTO : ANNOBIN_TOOL_ID_GCC;
  annobin_emit_start_sym_and_version_note ("", producer_char);

  /* On the PPC64 queueing this attachment results in:
       Error: operation combines symbols in different segments
     I do not known how to fix this at the moment, so the
     attachment is currently coditional upon target sym bias.  */
  if (! target_start_sym_bias)
    queue_attachment (CODE_SECTION, concat (CODE_SECTION, ANNOBIN_GROUP_NAME, NULL));
  emit_global_notes ("");

  /* GCC does not provide any way for a plugin to detect if hot/cold partitioning
     will be performed on a function, and hence a .text.hot and/or .text.unlikely
     section will be created.  So instead we create global notes to cover these
     two sections.  */
  annobin_emit_start_sym_and_version_note (HOT_SUFFIX, producer_char);
  queue_attachment (HOT_SECTION, concat (HOT_SECTION, ANNOBIN_GROUP_NAME, NULL));
  /* We have to emit notes for these other sections too, as we do not know
     which one(s) will actually end up containing any code.  Annocheck will
     ignore empty note ranges.  */
  emit_global_notes (HOT_SUFFIX);

  annobin_emit_start_sym_and_version_note (COLD_SUFFIX, producer_char);
  queue_attachment (COLD_SECTION, concat (COLD_SECTION, ANNOBIN_GROUP_NAME, NULL));
  emit_global_notes (COLD_SUFFIX);

  /* As of gcc 9, a .text.startup section can also be created.  */
  annobin_emit_start_sym_and_version_note (STARTUP_SUFFIX, producer_char);
  queue_attachment (STARTUP_SECTION, concat (STARTUP_SECTION, ANNOBIN_GROUP_NAME, NULL));
  emit_global_notes (STARTUP_SUFFIX);

  /* Presumably a .text.exit section can also be created, although I have not seen that yet.  */
  annobin_emit_start_sym_and_version_note (EXIT_SUFFIX, producer_char);
  queue_attachment (EXIT_SECTION, concat (EXIT_SECTION, ANNOBIN_GROUP_NAME, NULL));
  emit_global_notes (EXIT_SUFFIX);
}

static void
annobin_emit_end_symbol (const char * suffix)
{
  if (*suffix)
    {
      if (annobin_attach_type == group)
	fprintf (asm_out_file, "\t.pushsection %s%s, \"axG\", %%progbits, %s%s%s\n",
		 CODE_SECTION, suffix,
		 CODE_SECTION, suffix, ANNOBIN_GROUP_NAME);
      else
	fprintf (asm_out_file, "\t.pushsection %s%s, \"ax\", %%progbits\n", CODE_SECTION, suffix);

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
	 only target that uses symbol biasing.

	 FIXME: As of GCC 10 however the PPC64 LTO compiler does perform
	 the partitioning, so we do need the symbol to be in a special
	 section.  */
      if (target_start_sym_bias == 0
#if GCCPLUGIN_VERSION_MAJOR >= 10
	  || in_lto ()
#endif
	  )
	{
	  const char * extra_suffix = ".zzz";

	  if (annobin_attach_type == group)
	    /* Since we have issued the .attach, make sure that we include the group here.  */
	    fprintf (asm_out_file, "\t.section %s%s%s, \"axG\", %%progbits, %s%s%s\n",
		     CODE_SECTION, suffix, extra_suffix,
		     CODE_SECTION, suffix, ANNOBIN_GROUP_NAME);
	  else
	    fprintf (asm_out_file, "\t.section %s%s%s, \"ax\", %%progbits\n",
		     CODE_SECTION, suffix, extra_suffix);
	}
    }
  else
    fprintf (asm_out_file, "\t.pushsection %s\n", CODE_SECTION);

  fprintf (asm_out_file, "\t%s %s%s\n",
	   global_file_name_symbols ? ".global" : ".hidden",
	   annobin_current_endname, suffix);
  fprintf (asm_out_file, "%s%s:\n", annobin_current_endname, suffix);
  fprintf (asm_out_file, "\t.type %s%s, STT_NOTYPE\n", annobin_current_endname, suffix);
  fprintf (asm_out_file, "\t.size %s%s, 0\n", annobin_current_endname, suffix);
  annobin_inform (INFORM_VERBOSE, "Create symbol %s%s", annobin_current_endname, suffix);

  /* If there is a bias to the start symbol, we can end up with the case where
     the start symbol is after the end symbol.  (If the section is empty).
     Catch that and adjust the start symbol.  This also pacifies eu-elflint
     which complains about the start symbol being placed beyond the end of
     the section.

     FIXME: As of GCC 10 we cannot do this with LTO compilation as we have
     had to place the end symbol into a different section.  */
  if (target_start_sym_bias
#if GCCPLUGIN_VERSION_MAJOR >= 10
      && ! in_lto ()
#endif
      )
    {
      /* Note: we cannot test "start sym > end sym" as these symbols may not have values
	 yet, (due to the possibility of linker relaxation).  But we are allowed to
	 test for symbol equality.  So we fudge things a little....  */
     
      fprintf (asm_out_file, "\t.if %s%s == %s%s + %d\n", annobin_output_filesym, suffix,
	       annobin_current_endname, suffix, target_start_sym_bias);
      fprintf (asm_out_file, "\t  .set %s%s, %s%s\n", annobin_output_filesym, suffix,
	       annobin_current_endname, suffix);
      fprintf (asm_out_file, "\t.endif\n");
    }

  fprintf (asm_out_file, "\t.popsection\n");
}

static void
annobin_finish_unit (void * gcc_data, void * user_data)
{
  if (asm_out_file == NULL)
    {
      annobin_inform (INFORM_VERBOSE, "no unit end notes.");
      return;
    }

  /* It is possible that there is no code in the .text section.
     Eg because the compilation was run with the -ffunction-sections option.
     Nevertheless we generate this symbol because it is needed by the
     version note that was generated in annobin_create_global_notes().  */
  emit_queued_attachments ();

  annobin_emit_end_symbol ("");
  annobin_emit_end_symbol (HOT_SUFFIX);
  annobin_emit_end_symbol (COLD_SUFFIX);
  annobin_emit_end_symbol (STARTUP_SUFFIX);
  annobin_emit_end_symbol (EXIT_SUFFIX);
}

static void
annobin_display_version (void)
{
  annobin_inform (INFORM_ALWAYS, "Annobin GCC Plugin Version %d.%02d", ANNOBIN_VERSION / 100, ANNOBIN_VERSION % 100);
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
	annobin_display_version ();

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
	; // Deprecated.
      else if (streq (key, "no-dynamic-notes"))
	; // Deprecated.

      else if (streq (key, "static-notes"))
	; // Deprecated.
      else if (streq (key, "no-static-notes"))
	; // Deprecated.

      else if (streq (key, "attach"))
	annobin_attach_type = group;
      else if (streq (key, "no-attach"))
	annobin_attach_type = none;
      else if (streq (key, "link-order"))
	annobin_attach_type = link_order;
      else if (streq (key, "no-link-order"))
	annobin_attach_type = none;

      else if (streq (key, "active-checks"))
	annobin_active_checks = 2;
      else if (streq (key, "no-active-checks"))
	annobin_active_checks = 0;

      else if (streq (key, "ppc64-nops"))
	enable_ppc64_nops = true;
      else if (streq (key, "no-ppc64-nops"))
	enable_ppc64_nops = false;
      
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

  /* Create a file name symbol to be referenced by the notes.  */
  if (! init_annobin_output_filesym ())
    {
      ice ("Could not find output filename");
      /* We need a filesym, so invent one.  */
      annobin_output_filesym = (char *) "unknown_source";
    }

  if (BE_VERBOSE)
    annobin_display_version ();

  if (! plugin_default_version_check (version, & gcc_version))
    {
      bool fail = false;

      /* plugin_default_version_check is very strict and requires that the
	 major, minor and revision numbers all match.  Since annobin only
	 lightly touches gcc we assume that major number compatibility will
	 be sufficient.  [FIXME: It turns out that this is not entirely true...]  */
      if (strncmp (version->basever, gcc_version.basever, strchr (version->basever, '.') - version->basever))
	{
	  annobin_inform (INFORM_ALWAYS, _("Error: plugin built for compiler version (%s) but run with compiler version (%s)"),
			  gcc_version.basever, version->basever);
	  fail = true;
	}

      /* Since the plugin is not part of the gcc project, it is entirely
	 likely that it has been built on a different day.  This is not
	 a showstopper however, since compatibility will be retained as
	 long as the correct headers were used.  */
      if (! streq (version->datestamp, gcc_version.datestamp))
	annobin_inform (INFORM_VERBOSE, _("Plugin datestamp (%s) is different from compiler datestamp (%s) - ignored\n"),
			version->datestamp, gcc_version.datestamp);

      /* Unlikely, but also not serious.  */
      if (! streq (version->devphase, gcc_version.devphase))
	annobin_inform (INFORM_VERBOSE, _("Plugin built for compiler development phase (%s) not (%s) - ignored\n"),
			version->devphase, gcc_version.devphase);

      /* Theoretically this could be a problem, in practice it probably isn't.  */
      if (! streq (version->revision, gcc_version.revision))
	annobin_inform (INFORM_VERBOSE, _("Plugin built for compiler revision (%s) not (%s) - ignored\n"),
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
	      plugin_target_end = plugin_target + 6; /* strlen ("native")  */
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
	      annobin_inform (INFORM_ALWAYS, _("Error: plugin run on a %.*s compiler but built for a %.*s compiler\n"),
			      (int) (plugin_target_end - plugin_target), plugin_target,
			      (int) (gcc_target_end - gcc_target), gcc_target);
	      fail = true;
	    }
	  else
	    {
	      annobin_inform (INFORM_VERBOSE, _("Plugin run on a compiler configured as (%s) not (%s) - ignored\n"),
			      version->configuration_arguments, gcc_version.configuration_arguments);
	    }
	}

      if (fail)
	return 1;
    }
  
  /* Record global compiler options.
     NB/ The format of these strings is important, as knowledge
     of their layout is embedded into hardended.c.  */
  run_version   = concat ("running gcc ", version->basever, " ", version->datestamp, NULL);
  build_version = concat ("annobin gcc ", gcc_version.basever, " ", gcc_version.datestamp, NULL);

  annobin_inform (INFORM_VERBOSE, "Plugin built by %s, running on %s", build_version + 8, run_version + 8);

  if (annobin_save_target_specific_information () == 1)
    return 1;

  target_start_sym_bias = annobin_target_start_symbol_bias ();
  if (annobin_attach_type == not_set)
    {
#if GCCPLUGIN_VERSION_MAJOR >= 11
      /* For the PPC64LE default to using link order attachment as group attachments do not work.
	 Only do this if the target supports link_order sections.  For now we use a test of the
	 GCC version as an approximation to the GAS version that is needed.  See BZ 2016458 for
         an example of where this solution is needed.  */
      if (target_start_sym_bias != 0)
	annobin_attach_type = link_order;
      else
#endif
	annobin_attach_type = group;
    }

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

  register_callback ("annobin: Register per-function end symbols",
		     PLUGIN_ALL_PASSES_END,
		     annobin_create_function_end_symbol,
		     NULL);

  register_callback ("annobin: Generate final annotations",
		     PLUGIN_FINISH_UNIT,
		     annobin_finish_unit,
		     NULL);
  return 0;
}
