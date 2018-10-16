/* Checks the builder of the binary file. 
   Copyright (c) 2018 Red Hat.

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

#include "annocheck.h"

static const char * istool = NULL;
static const char * nottool = NULL;
static const char * last_tool = NULL;

static bool disabled = true;

static bool found_builder;
static bool all = false;

static bool
builtby_start (annocheck_data * data)
{
  found_builder = false;
  last_tool = NULL;
  return true;
}

static bool
builtby_interesting_sec (annocheck_data *     data,
			 annocheck_section *  sec)
{
  if (disabled)
    return false;

  if (! all && found_builder)
    return false;

  if (sec->shdr.sh_size == 0)
    return false;

  if (streq (sec->secname, ".comment"))
    return true;

  return sec->shdr.sh_type == SHT_NOTE;
}

static bool
found (const char * source, const char * filename, const char * tool)
{
  /* FIXME: Regexps would be better.  */
  if (nottool != NULL && streq (nottool, tool))
    return true;

  if (istool != NULL && ! streq (istool, tool))
    return true;

  if (last_tool && streq (tool, last_tool))
    return true;

  if (all)
    einfo (INFO, "%s was built by %s [%s]", filename, tool, source);
  else
    einfo (INFO, "%s was built by %s", filename, tool);
    
  found_builder = true;
  last_tool = tool;
  return all; /* Stop further searches unless checking for all builder notes.  */
}

static bool
builtby_note_walker (annocheck_data *     data,
		     annocheck_section *  sec,
		     GElf_Nhdr *            note,
		     size_t                 name_offset,
		     size_t                 data_offset,
		     void *                 ptr)
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

  return found ("annobin note", (const char *) ptr, namedata + pos + 1);
}

static bool
builtby_check_sec (annocheck_data *     data,
		   annocheck_section *  sec)
{
  if (streq (sec->secname, ".comment"))
    {
      const char * tool = (const char *) sec->data->d_buf;

      if (sec->data->d_size == 0)
	return true; /* The .comment section is empty, so keep on searching.  */

      if (tool[0] == 0)
	tool ++; /* Not sure why this can happen, but it does.  */

      return found (".comment section", data->filename, tool);
    }

  if (streq (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME))
    return annocheck_walk_notes (data, sec, builtby_note_walker, (void *) data->filename);

  return true; /* Allow the search to continue.  */
}

/* Look for DW_AT_producer attributes.  */

static bool
builtby_dwarf_walker (annocheck_data * data, Dwarf * dwarf, Dwarf_Die * die, void * ptr)
{
  Dwarf_Attribute  attr;
  const char *     string;

  if (dwarf_attr (die, DW_AT_producer, & attr) == NULL)
    return true;

  string = dwarf_formstring (& attr);
  if (string == NULL)
    return einfo (ERROR, "%s: DWARF DW_AT_producer attribute does not have a string value", data->filename);

  found ("DWARF attribute", data->filename, string);
  return all;
}

static bool
builtby_finish (annocheck_data * data)
{
  if (disabled)
    return true;

  if (found_builder && ! all)
    return true;

  (void) annocheck_walk_dwarf (data, builtby_dwarf_walker, NULL);
    
  if (! found_builder)
    einfo (INFO, "%s: could not determine builder", data->filename);

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
  einfo (INFO, "Version 1.0");
}

struct checker builtby_checker = 
{
  "Built By",
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
  if (! annocheck_add_checker (& builtby_checker, major_version))
    disabled = true;
}
