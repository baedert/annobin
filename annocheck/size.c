/* Computes the cumulative size of section(s) in binary files. 
   Copyright (c) 2018 - 2022 Red Hat.

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

static bool disabled = true;
static bool human = false;

static Elf64_Word  sec_need_flags = 0;
static Elf64_Word  sec_not_flags = 0;
static Elf64_Word  sec_flag_size = 0;
static uint        sec_flag_match = 0;

static Elf64_Word  seg_need_flags = 0;
static Elf64_Word  seg_not_flags = 0;
static Elf64_Word  seg_flag_size = 0;
static uint        seg_flag_match = 0;

static bool        track_total_size = false;
static unsigned long long  total_sections_size;

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
    einfo (PARTIAL, "%#llx bytes", size);
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

  if (track_total_size)
    total_sections_size += sec->shdr.sh_size;
  
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

  if (sec_need_flags || sec_not_flags)
    {
      if ((sec->shdr.sh_flags & sec_need_flags) == sec_need_flags
	  && (sec->shdr.sh_flags & sec_not_flags) == 0)
	{
	  if (BE_VERBOSE)
	    {
	      einfo (VERBOSE, "%s: flag match for section %s, size: ",
		     data->filename, sec->secname);
	      print_size (sec->shdr.sh_size);
	      einfo (PARTIAL, "\n");
	    }
	  sec_flag_match ++;
	  sec_flag_size += sec->shdr.sh_size;
	}
    }

  /* We do not need any more information from the section, so there is no
     need to run the checker.  */
  return false;
}

static bool
size_interesting_seg (annocheck_data *     data,
		      annocheck_segment *  seg)
{
  if (disabled)
    return false;

  if (seg_need_flags || seg_not_flags)
    {
      if ((seg->phdr->p_flags & seg_need_flags) == seg_need_flags
	  && (seg->phdr->p_flags & seg_not_flags) == 0)
	{
	  if (BE_VERBOSE)
	    {
	      einfo (VERBOSE, "%s: flag match for segment %d, size: ",
		     data->filename, seg->number);
	      print_size (seg->phdr->p_memsz);
	      einfo (PARTIAL, "\n");
	    }

	  seg_flag_match ++;
	  seg_flag_size += seg->phdr->p_memsz;
	}
    }

  /* We do not need any more information from the segment,
     so there is no need to run the checker.  */
  return false;
}

/* This function is needed so that a data transfer file will be created.  */

static void
size_start_scan (uint level, const char * datafile)
{
  if (level != 0)
    return;

  total_sections_size = 0;
  sec_flag_size = 0;
  sec_flag_match = 0;
  seg_flag_size = 0;
  seg_flag_match = 0;
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

      uint sec_count, seg_count;
      unsigned long long sec_size, seg_size;

      if (fscanf (f, "%u %llx %u %llx\n", & sec_count, & sec_size, & seg_count, & seg_size) != 4)
	{
	  einfo (WARN, "Unable to locate section/segment flag size & counts");
	}
      else
	{
	  sec_flag_match += sec_count;
	  sec_flag_size += sec_size;
	  seg_flag_match += seg_count;
	  seg_flag_size += seg_size;
	}

      unsigned long long sections_size_so_far;
      if (fscanf (f, "%llx", & sections_size_so_far) != 1)
	{
	  einfo (WARN, "Unable to locate total sections size");
	}
      else
	total_sections_size += sections_size_so_far;

      fclose (f);
    }

  if (level == 0)
    {
      Elf64_Word sec_match_total = 0;

      for (sec = sec_list; sec != NULL; sec = sec->next)
	{
	  einfo (INFO, "Section '%s' found in %u files, total size: ", sec->name, sec->num_found);
	  print_size (sec->size);
	  einfo (PARTIAL, "\n");
	  sec_match_total += sec->size;
	}

      if (sec_need_flags || sec_not_flags)
	{
	  einfo (INFO, "%u sections match flag requirements, total size: ", sec_flag_match);
	  print_size (sec_flag_size);
	  einfo (PARTIAL, "\n");
	}
	
      if (seg_need_flags || seg_not_flags)
	{
	  einfo (INFO, "%u segments match flag requirements, total size: ", seg_flag_match);
	  print_size (seg_flag_size);
	  einfo (PARTIAL, "\n");
	}

      if (track_total_size)
	{
	  einfo (INFO, "total size of all sections in all examined files: ");
	  print_size (total_sections_size);
	  einfo (PARTIAL, "\n");

	  if (sec_match_total && total_sections_size)
	    {
	      einfo (INFO, "Ratio of matched section sizes to total section sizess: %lld%%\n",
		     (sec_match_total * 100) / total_sections_size);
	    }
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
	  einfo (WARN, "Unable to open datafile %s", datafile);
	  return;
	}

      for (sec = sec_list; sec != NULL; sec = sec->next)
	fprintf (f, "%s %llx %x\n", sec->name, sec->size, sec->num_found);

      fprintf (f, "%u %llx %u %llx\n",
	       sec_flag_match, (unsigned long long) sec_flag_size,
	       seg_flag_match, (unsigned long long) seg_flag_size);

      fprintf (f, "%llx\n", (unsigned long long) total_sections_size);

      fclose (f);
    }
}

static bool
size_process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
  if (arg[0] == '-')
    ++ arg;
  if (arg[0] == '-')
    ++ arg;

  if (const_strneq (arg, "sec-flags="))
    {
      const char * flag = arg + strlen ("size-sec-flags=");
      Elf64_Word * addto = & sec_need_flags;
      
      disabled = false;

      while (*flag)
	{
	  switch (*flag)
	    {
	    case '!':
	      /* Inverts the meaning of the following flags.  */
	      addto = & sec_not_flags;
	      break;
	    case 'w':
	    case 'W':
	      * addto |= SHF_WRITE;
	      break;
	    case 'a':
	    case 'A':
	      * addto |= SHF_ALLOC;
	      break;
	    case 'x':
	    case 'X':
	      * addto |= SHF_EXECINSTR;
	      break;
	    default:
	      /* FIXME: Add more section flags.  */
	      einfo (WARN, "Unrecognised section flag '%c'", *flag);
	      break;
	    }
	  ++ flag;
	}

      return true;
    }
  
  if (const_strneq (arg, "seg-flags="))
    {
      const char * flag = arg + strlen ("size-seg-flags=");
      Elf64_Word * addto = & seg_need_flags;

      disabled = false;

      while (*flag)
	{
	  switch (*flag)
	    {
	    case '!':
	      /* Inverts the meaning of the following flags.  */
	      addto = & seg_not_flags;
	      break;
	    case 'w':
	    case 'W':
	      * addto |= PF_W;
	      break;
	    case 'r':
	    case 'R':
	      * addto |= PF_R;
	      break;
	    case 'x':
	    case 'X':
	      * addto |= PF_X;
	      break;
	    default:
	      /* FIXME: Add more segment flags.  */
	      einfo (WARN, "Unrecognised segment flag '%c'", *flag);
	      break;
	    }
	  ++ flag;
	}

      return true;
    }
  
  if (const_strneq (arg, "section-size") /* Deprecated.  */
      || const_strneq (arg, "sec"))
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

  if (streq (arg, "total"))
    {
      track_total_size = true;
      return true;
    }
  
  if (streq (arg, "human"))
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
  einfo (INFO, " --size-sec=<NAME>   Records the size of section NAME.  Can be used more than once");
  einfo (INFO, " If --verbose has been enabled then the size of every encountered NAME section will be displayed");
  einfo (INFO, " Use --size-human to display the sizes in human readable amounts");
  einfo (INFO, " Use --size-total to display the total size of all sections examined");
  einfo (INFO, " Use --size-sec-flags=[!WAX] to count the size of any section with/without the specified flags");
  einfo (INFO, " Use --size-seg-flags=[!WRX] to count the size of any segment with/without the specified flags");
}

static void
size_version (void)
{
  einfo (INFO, "Version 1.2");
}

struct checker size_checker = 
{
  "Size",
  NULL, /* file_start */
  size_interesting_sec,
  NULL, /* check_sec */
  size_interesting_seg,
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
  if (! annocheck_add_checker (& size_checker, ANNOBIN_VERSION / 100))
    disabled = true;
}
