/* Checks the builder of the binary file. 
   Copyright (c) 2018 - 2020 Red Hat.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  You should have received a copy of the GNU General Public
  License along with this program; see the file COPYING3. If not,
  see <http://www.gnu.org/licenses/>.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "annobin-global.h"
#include "annocheck.h"

static const char * istool = NULL;
static const char * nottool = NULL;

static bool disabled = true;
static bool all = false;
static bool is_obj = false;

static bool
builtby_start (annocheck_data * data)
{
  if (data->is_32bit)
    is_obj = elf32_getehdr (data->elf)->e_type == ET_REL;
  else
    is_obj = elf64_getehdr (data->elf)->e_type == ET_REL;

  return true;
}

static bool
builtby_interesting_sec (annocheck_data *     data,
			 annocheck_section *  sec)
{
  if (disabled)
    return false;

  if (sec->shdr.sh_size == 0)
    return false;

  if (streq (sec->secname, ".comment"))
    return true;

  return sec->shdr.sh_type == SHT_NOTE;
}

struct entry
{
  const char * program;
  const char * version;
  struct entry * prev;
  struct entry * next;
};

static struct entry * first_entry = NULL;

static bool
add_tool (const char * program, const char * version)
{
  struct entry * new_entry;
  struct entry * entry;

  for (entry = first_entry; entry != NULL; entry = entry->next)
    {
      if (streq (entry->program, program)
	  && (strstr (version, entry->version)
	      || strstr (entry->version, version)))
	return false;
    }
  
  new_entry = xmalloc (sizeof * new_entry);
  new_entry->program = program;
  new_entry->version = version;
  new_entry->next = first_entry;
  new_entry->prev = NULL;
  first_entry = new_entry;
  return true;
}

#define STR_AND_LEN(str)  (str), sizeof (str) - 1

static void
parse_tool (const char * tool, const char ** program, const char ** version, const char * source)
{
  static struct
  {
    const char * prefix;
    const int    length;
    const char * program;
  }
  prefixes [] =
    {
     { STR_AND_LEN ("gcc "), "gcc" }, /* From annobin notes.  */
     { STR_AND_LEN ("running gcc "), "gcc" }, /* From annobin notes.  */
     { STR_AND_LEN ("annobin gcc "), "gcc" }, /* From annobin notes.  */
     { STR_AND_LEN ("annobin gcc "), "gcc" }, /* From annobin notes.  */
     { STR_AND_LEN ("GCC: (GNU) "), "gcc" }, /* .comment section.  */
     { STR_AND_LEN ("GNU C89 "), "gcc" }, /* DW_AT_producer.  */
     { STR_AND_LEN ("GNU C99 "), "gcc" }, /* DW_AT_producer.  */
     { STR_AND_LEN ("GNU C11 "), "gcc" }, /* DW_AT_producer.  */
     { STR_AND_LEN ("GNU C17 "), "gcc" }, /* DW_AT_producer.  */
     { STR_AND_LEN ("GNU Fortran2008 "), "gfortran" }, /* DW_AT_producer.  */
     { STR_AND_LEN ("rustc version "), "rust" }, /* DW_AT_producer.  */
     { STR_AND_LEN ("Go cmd/compile "), "go" }, /* DW_AT_producer.  */
     { STR_AND_LEN ("GNU AS "), "as" }, /* DW_AT_producer.  */
     { STR_AND_LEN ("Guile "), "guile" }, /* DW_AT_producer.  */
     { STR_AND_LEN ("GHC "), "ghc" }, /* DW_AT_producer.  */
     { STR_AND_LEN ("LDC "), "d" }, /* DW_AT_producer.  */
     { STR_AND_LEN ("ldc "), "d" }, /* .comment section.  */
     { STR_AND_LEN ("running on clang version "), "clang" }, /* From annobin notes.  */
     { STR_AND_LEN ("clang version "), "clang" },  /* .comment section.  */
     { STR_AND_LEN ("Linker: LLD "), "lld" } /* .comment section.  */
    };

  int i;
  for (i = ARRAY_SIZE (prefixes); i--;)
    {
      if (strneq (prefixes[i].prefix, tool, prefixes[i].length))
	{
	  * program = prefixes[i].program;
	  * version = tool + prefixes[i].length;
	  return;
	}
    }

  einfo (VERBOSE, "UNEXPECTED TOOL STRING: %s (source %s)", tool, source);
  * program = tool;
  char * space = strchr (tool, ' ');
  if (space)
    * version = space + 1;
  else
    * version = "";
}

static void
found (const char * source, const char * filename, const char * tool)
{
  const char * program;
  const char * version;

  parse_tool (tool, & program, & version, source);
  
  /* FIXME: Regexps would be better.  */
  if (nottool != NULL && streq (nottool, program))
    return;

  if (istool != NULL && ! streq (istool, program))
    return;

  bool is_new = add_tool (program, version);

  if (!all && !is_new)
    return;

  const	char * close_paren = strchr (version, ')');
  int len = 0;
  if (close_paren)
    len	= (close_paren - version) + 1;  

  einfo (PARTIAL, "%s was built by %s (version ", filename, program);

  if (len)
    einfo (PARTIAL, "%.*s", len, version);
  else
    einfo (PARTIAL, "%s", version);

  if (all)
    einfo (PARTIAL, ") [%s]\n", source);
  else
    einfo (PARTIAL, ")\n");
}

static bool
builtby_note_walker (annocheck_data *     data,
		     annocheck_section *  sec,
		     GElf_Nhdr *          note,
		     size_t               name_offset,
		     size_t               data_offset,
		     void *               ptr)
{
  if (note->n_type != NT_GNU_BUILD_ATTRIBUTE_OPEN)
    return true;

  if (note->n_namesz < 3)
    return false;

  const char * namedata = sec->data->d_buf + name_offset;
  
  uint pos = (namedata[0] == 'G' ? 3 : 1);

  /* Look for: GA$<tool>gcc 7.0.0 20161212.  */
  if (namedata[pos] != GNU_BUILD_ATTRIBUTE_TOOL)
    return true;

  if (namedata[pos - 1] != GNU_BUILD_ATTRIBUTE_TYPE_STRING)
    return false;

  /* Note - we cannot use the STR_AND_LEN macro here as some
     headers defined strncmp as a macro, and macros are not
     expanded inside other macros.  */
  if (strncmp ((const char *) namedata + pos + 1, "annobin built", sizeof ("annobin built") - 1) != 0)
    found ("annobin note", (const char *) ptr, namedata + pos + 1);

  return true;
}

static bool
builtby_check_sec (annocheck_data *     data,
		   annocheck_section *  sec)
{
  if (streq (sec->secname, ".comment"))
    {
      const char * tool = (const char *) sec->data->d_buf;
      const char * tool_end = tool + sec->data->d_size;

      if (sec->data->d_size == 0)
	return true; /* The .comment section is empty, so keep on searching.  */

      if (tool[0] == 0)
	tool ++; /* Not sure why this can happen, but it does.  */

      while (tool < tool_end)
	{
	  if (* tool)
	    found (".comment section", data->filename, tool);

	  tool += strlen (tool) + 1;
	}

      return true;
    }

  if (streq (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME))
    return annocheck_walk_notes (data, sec, builtby_note_walker, (void *) data->filename);

  if (streq (sec->secname, ".note.go.buildid"))
    found (".note.go.buildid", data->filename, "Go cmd/compile ?.?.?");

  return true; /* Allow the search to continue.  */
}

/* Look for DW_AT_producer attributes.  */

static bool
builtby_dwarf_walker (annocheck_data * data, Dwarf * dwarf, Dwarf_Die * die, void * ptr)
{
  Dwarf_Attribute  attr;
  const char *     string;

  if (dwarf_attr (die, DW_AT_producer, & attr) == NULL)
    {
      einfo (VERBOSE, "%s: DW_AT_producer string not found", data->filename);
      return true;
    }

  string = dwarf_formstring (& attr);
  if (string == NULL)
    return einfo (ERROR, "%s: DWARF DW_AT_producer attribute does not have a string value", data->filename);

  einfo (VERBOSE, "%s: DW_AT_producer string: %s", data->filename, string);

  found ("DWARF attribute", data->filename, string);
  
  return true;
}

static bool
builtby_finish (annocheck_data * data)
{
  if (disabled)
    return true;

  if (is_obj)
    /* Object files contain unrelocated DWARF debug info,
       which can lead to bogus DW_AT_producer strings.  */
    einfo (VERBOSE, "%s: ignoring unrelocated DWARF debug info", data->filename);
  else
    (void) annocheck_walk_dwarf (data, builtby_dwarf_walker, NULL);
    
  if (first_entry == NULL)
    {
      if (istool)
	einfo (VERBOSE, "%s: not built by %s", data->filename, istool);
      else if (nottool)
	einfo (VERBOSE, "%s: was built by %s", data->filename, nottool);
      else
	einfo (INFO, "%s: could not determine builder", data->filename);
    }
  else
    {
      struct entry * entry;
      struct entry * next = NULL;

      for (entry = first_entry; entry != NULL; entry = next)
	{
	  next = entry->next;
	  free (entry);
	}

      first_entry = NULL;
    }
  return true;
}

static bool
builtby_process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
  const char * parameter;

  if (streq (arg, "--enable-builtby") || streq (arg, "--enable-built-by"))
    {
      disabled = false;
      return true;
    }

  if (streq (arg, "--disable-builtby") || streq (arg, "--disable-built-by"))
    {
      disabled = true;
      return true;
    }

  if (streq (arg, "--all"))
    {
      all = true;
      return true;
    }

  if (const_strneq (arg, "--tool="))
    {
      if ((parameter = strchr (arg, '=')) == NULL)
	{
	  istool = argv[* next];
	  * next = * next + 1;
	}
      else
	istool = parameter + 1;
      
      return true;
    }

  if (const_strneq (arg, "--nottool="))
    {
      if ((parameter = strchr (arg, '=')) == NULL)
	{
	  nottool = argv[* next];
	  * next = * next + 1;
	}
      else
	nottool = parameter + 1;
      return true;
    }

  return false;
}

static void
builtby_usage (void)
{
  einfo (INFO, "Determines what tool built the given file(s)");
  einfo (INFO, " NOTE: This tool is disabled by default.  To enable it use: --enable-builtby");
  einfo (INFO, " The checks can be made conditional by using the following options:");
  einfo (INFO, "    --all             Report all builder identification strings");
  einfo (INFO, "    --tool=<NAME>     Only report binaries built by <NAME>");
  einfo (INFO, "    --nottool=<NAME>  Skip binaries built by <NAME>");
#if 0
  einfo (INFO, "    --before=<DATE>   Only report binaries built before <DATE>");
  einfo (INFO, "    --after=<DATE>    Only report binaries built after <DATE>");
  einfo (INFO, "    --minver=<VER>    Only report binaries built by version <VER> or higher");
  einfo (INFO, "    --maxver=<VER>    Only report binaries built by version <VER> or lower");
  einfo (INFO, "  <NAME> is just a string, not a regular expression");
  einfo (INFO, "  <DATE> format is YYYYMMDD.  For example: 20161230");
  einfo (INFO, "  <VER> is a version string in the form V.V.V  For example: 6.1.2");
  einfo (INFO, "The --before and --after options can be used together to specify a date");
  einfo (INFO, "range which should be reported.  Similarly the --minver and --maxver");
  einfo (INFO, "options can be used together to specify a version range.\n");
#endif
}

static void
builtby_version (void)
{
  einfo (INFO, "Version 1.1");
}

struct checker builtby_checker = 
{
  "BuiltBy",
  builtby_start,
  builtby_interesting_sec,
  builtby_check_sec,
  NULL, /* interesting_seg */
  NULL, /* check_seg */
  builtby_finish,
  builtby_process_arg,
  builtby_usage,
  builtby_version,
  NULL, /* start_scan */
  NULL, /* end_scan */
  NULL /* internal */
};

static __attribute__((constructor)) void
builtby_register_checker (void) 
{
  if (! annocheck_add_checker (& builtby_checker, ANNOBIN_VERSION / 100))
    disabled = true;
}
