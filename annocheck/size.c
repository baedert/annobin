/* Computes the cumulative size of section(s) in binary files. 
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

static bool disabled = true;
static bool human = false;

typedef struct sec_size
{
  const char *        name;
  unsigned long long  size;
  uint                num_found;
  struct sec_size *   next;
} sec_size;

static sec_size * sec_list = NULL;
  
static void
add_section (const char * name)
{
  sec_size * section = XCNEW (sec_size);

  /* FIXME: Check for duplicate section names.  */
  section->name = name;
  section->next = sec_list;
  sec_list = section;
}

static void
print_size (unsigned long long size)
{
  if (!human)
    einfo (PARTIAL, "%#llx", size);
  else if (size < 1024)
    einfo (PARTIAL, "%lld bytes", size);
  else if (size < (1024 * 1024))
    einfo (PARTIAL, "%lldKb", size >> 10);
  else if (size < (1024LL * 1024LL * 1024LL))
    einfo (PARTIAL, "%lldMb", size >> 20);
  else
    einfo (PARTIAL, "%lldGb", size >> 30);
}

static bool
size_interesting_sec (annocheck_data *     data,
		      annocheck_section *  sec)
{
  if (disabled)
    return false;

  sec_size * sz;

  for (sz = sec_list; sz != NULL; sz = sz->next)
    {
      if (streq (sz->name, sec->secname))
	{
	  if (BE_VERBOSE)
	    {
	      einfo (VERBOSE, "%s: %s: ", data->filename, sec->secname);
	      print_size (sec->shdr.sh_size);
	      einfo (PARTIAL, "\n");
	    }

	  sz->size += sec->shdr.sh_size;
	  sz->num_found ++;
	  break;
	}
    }

  /* We do not need any more information from the section, so there is no
     need to run the checker.  */
  return false;
}

/* This function is needed so that a data transfer file will be created.  */

static void
size_start_scan (uint level, const char * datafile)
{
}

static void
size_end_scan (uint level, const char * datafile)
{
  sec_size * sec;

  if (disabled)
    return;

  FILE * f = fopen (datafile, "r");
  if (f != NULL)
    {
      einfo (VERBOSE2, "Loading recursed size data from %s", datafile);

      for (sec = sec_list; sec != NULL; sec = sec->next)
	{
	  const char *        name = NULL;
	  unsigned long long  size = 0;
	  uint                num;

	  if (fscanf (f, "%ms %llx %x\n", & name, & size, & num) != 3)
	    {
	      einfo (WARN, "unable to parse the contents of %s", datafile);
	    }
	  else if (name == NULL)
	    {
	      einfo (WARN, "parsing data file: unable to parse section name");
	    }
	  else if (streq (name, sec->name))
	    {
	      sec->size += size;
	      sec->num_found += num;
	    }
	  else
	    {
	      einfo (WARN, "parsing data file: expected section %s found section %s",
		     sec->name, name);
	    }
	}

      fclose (f);
    }

  if (level == 0)
    {
      for (sec = sec_list; sec != NULL; sec = sec->next)
	{
	  einfo (INFO, "Section '%s' found in %u files, total size: ", sec->name, sec->num_found);
	  print_size (sec->size);
	  einfo (PARTIAL, "\n");
	}

      einfo (VERBOSE2, "Deleting data file %s", datafile);
      unlink (datafile);
    }
  else
    {
      einfo (VERBOSE2, "Storing size data in %s", datafile);

      /* Write the accumulated sizes into the file.  */
      FILE * f = fopen (datafile, "w");

      if (f == NULL)
	{
	  einfo (WARN, "unable to open datafile %s", datafile);
	  return;
	}

      for (sec = sec_list; sec != NULL; sec = sec->next)
	fprintf (f, "%s %llx %x\n", sec->name, sec->size, sec->num_found);

      fclose (f);
    }
}

static bool
size_process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
  if (const_strneq (arg, "--section-size"))
    {
      const char * parameter;
      const char * sought;

      if ((parameter = strchr (arg, '=')) == NULL)
	{
	  sought = argv[* next];
	  * next = * next + 1;
	}
      else
	sought = parameter + 1;

      if (sought != NULL && * sought != 0)
	{
	  disabled = false;
	  add_section (sought);
	}

      return true;
    }

  if (streq (arg, "--human"))
    {
      human = true;
      return true;
    }

  return false;
}

static void
size_usage (void)
{
  einfo (INFO, "Computes the cumulative size of the specified section(s) in the input files");
  einfo (INFO, " NOTE: This tool is disabled by default.  To enable it use: --section-size=<NAME>");
  einfo (INFO, " --section-size=<NAME>   Records the size of section NAME.  Can be used more than once");
  einfo (INFO, " If --verbose has been enabled then the size of every encountered NAME section will be displayed");
  einfo (INFO, " Use --human to display the sizes in human readable amounts");
}

static void
size_version (void)
{
  einfo (INFO, "Version 1.0");
}

struct checker size_checker = 
{
  "Section_Size",
  NULL, /* file_start */
  size_interesting_sec,
  NULL, /* check_sec */
  NULL, /* interesting_seg */
  NULL, /* check_seg */
  NULL, /* end_file */
  size_process_arg,
  size_usage,
  size_version,
  size_start_scan,
  size_end_scan,
  NULL /* internal */
};

static __attribute__((constructor)) void
size_register_checker (void) 
{
  if (! annocheck_add_checker (& size_checker, major_version))
    disabled = true;
}
