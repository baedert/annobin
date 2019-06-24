/* Displays the Annobin notes in binary files.
   Copyright (c) 2019 Red Hat.

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
#include <time.h>

typedef struct local_note
{
  ulong start;
  ulong end;
  uint value;
  const char * data;
} local_note;


static bool          disabled = true;
static bool          is_little_endian;
static Elf64_Half    e_machine;
static Elf64_Half    e_type;
static ulong         saved_start;
static ulong         saved_end;
static local_note *  saved_notes = NULL;
static uint          num_saved_notes = 0;
static uint          num_allocated_notes = 0;

static bool
notes_start_file (annocheck_data * data)
{
  assert (saved_notes == NULL && num_saved_notes == 0 && num_allocated_notes == 0);

  if (data->is_32bit)
    {
      Elf32_Ehdr * hdr = elf32_getehdr (data->elf);

      e_type = hdr->e_type;
      e_machine = hdr->e_machine;
      is_little_endian = hdr->e_ident[EI_DATA] != ELFDATA2MSB;
    }
  else
    {
      Elf64_Ehdr * hdr = elf64_getehdr (data->elf);

      e_type = hdr->e_type;
      e_machine = hdr->e_machine;
      is_little_endian = hdr->e_ident[EI_DATA] != ELFDATA2MSB;
    }

  return true;
}

static bool
notes_interesting_sec (annocheck_data *     data,
		       annocheck_section *  sec)
{
  if (disabled)
    return false;

  return sec->shdr.sh_type == SHT_NOTE && const_strneq (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME);
}

static void
record_new_range (ulong start, ulong end)
{
  saved_start = start;
  saved_end   = end;
}

#define RANGE_ALLOC_DELTA    16

static void
record_note (uint value, const char * data)
{
  if (num_saved_notes >= num_allocated_notes)
    {
      num_allocated_notes += RANGE_ALLOC_DELTA;
      size_t num = num_allocated_notes * sizeof saved_notes[0];

      if (saved_notes == NULL)
	saved_notes = xmalloc (num);
      else
	saved_notes = xrealloc (saved_notes, num);
    }

  local_note * note = saved_notes + num_saved_notes;
  note->start = saved_start;
  note->end   = saved_end;
  note->value = value;
  note->data  = data;
  ++ num_saved_notes;
}

static bool
notes_walk (annocheck_data *     data,
	    annocheck_section *  sec,
	    GElf_Nhdr *          note,
	    size_t               name_offset,
	    size_t               data_offset,
	    void *               ptr)
{
  if (note->n_type != NT_GNU_BUILD_ATTRIBUTE_OPEN
      && note->n_type != NT_GNU_BUILD_ATTRIBUTE_FUNC)
    {
      einfo (ERROR, "%s: Unrecognised annobin note type %d", data->filename, note->n_type);
      return false;
    }

  if (note->n_namesz < 3)
    {
      einfo (FAIL, "%s: Corrupt annobin note, name size: %x", data->filename, note->n_namesz);
      return false;
    }

  if (note->n_descsz > 0)
    {
      ulong start = 0;
      ulong end = 0;
      const unsigned char * descdata = sec->data->d_buf + data_offset;

      /* FIXME: Should we add support for earlier versions of
	 the annobin notes which did not include an end symbol ?  */

      if (note->n_descsz == 16)
	{
	  int i;
	  int shift;

	  if (is_little_endian)
	    {
	      for (shift = i = 0; i < 8; i++)
		{
		  ulong byte = descdata[i];

		  start |= byte << shift;
		  byte = descdata[i + 8];
		  end |= byte << shift;

		  shift += 8;
		}
	    }
	  else
	    {
	      for (shift = 0, i = 7; i >= 0; i--)
		{
		  ulong byte = descdata[i];

		  start |= byte << shift;
		  byte = descdata[i + 8];
		  end |= byte << shift;

		  shift += 8;
		}
	    }
	}
      else if (note->n_descsz == 8)
	{
	  if (is_little_endian)
	    {
	      start = descdata[0] | (descdata[1] << 8) | (descdata[2] << 16) | (((unsigned int) descdata[3]) << 24);
	      end   = descdata[4] | (descdata[5] << 8) | (descdata[6] << 16) | (((unsigned int) descdata[7]) << 24);
	    }
	  else
	    {
	      start = descdata[3] | (descdata[2] << 8) | (descdata[1] << 16) | (((unsigned int) descdata[0]) << 24);
	      end   = descdata[7] | (descdata[6] << 8) | (descdata[5] << 16) | (((unsigned int) descdata[4]) << 24);
	    }
	}
      else
	{
	  einfo (FAIL, "%s: Corrupt annobin note, desc size: %x",
		 data->filename, note->n_descsz);
	  return false;
	}

      if (start > end)
	{
	  if (e_machine == EM_PPC64 && (start - end) <= 2)
	    /* On the PPC64, start symbols are biased by 2, but end symbols are not...  */
	    start = end;
	  else
	    {
	      einfo (FAIL, "%s: Corrupt annobin note, start address %#lx > end address %#lx",
		     data->filename, start, end);
	      return true;
	    }
	}

      record_new_range (start, end);
    }

  const char *  namedata = sec->data->d_buf + name_offset;
  uint          pos = (namedata[0] == 'G' ? 3 : 1);
  char          attr_type = namedata[pos - 1];
  const char *  attr = namedata + pos;

  /* Advance pos to the attribute's value.  */
  if (! isprint (* attr))
    pos ++;
  else
    pos += strlen (namedata + pos) + 1;

  const char *  string = namedata + pos;
  uint          value = -1;

  switch (attr_type)
    {
    case GNU_BUILD_ATTRIBUTE_TYPE_NUMERIC:
      {
	uint shift = 0;
	int bytes = (namedata + note->n_namesz) - string;

	value = 0;
	if (bytes > 0)
	  bytes --;
	while (bytes --)
	  {
	    uint byte = (* string ++) & 0xff;

	    /* Note - the watermark protocol dictates that numeric values are
	       always stored in little endian format, even if the target uses
	       big-endian.  */
	    value |= byte << shift;
	    shift += 8;
	  }
      }
      break;
    case GNU_BUILD_ATTRIBUTE_TYPE_STRING:
      break;
    case GNU_BUILD_ATTRIBUTE_TYPE_BOOL_TRUE:
      value = 1;
      break;
    case GNU_BUILD_ATTRIBUTE_TYPE_BOOL_FALSE:
      value = 0;
      break;
    default:
      einfo (VERBOSE, "ICE: Unrecognised annobin note type %d", attr_type);
      return true;
    }

  record_note (value, attr);

  return true;
}

static bool
notes_check_sec (annocheck_data *     data,
		 annocheck_section *  sec)
{
  if (disabled)
    return false;

  saved_start = saved_end = 0;

  return annocheck_walk_notes (data, sec, notes_walk, NULL);
}

static signed int
compare_range (const void * r1, const void * r2)
{
  local_note * n1 = (local_note *) r1;
  local_note * n2 = (local_note *) r2;

  if (n1->end < n2->start)
    return -1;

  if (n1->start > n2->end)
    return 1;

  /* Overlap - we should merge the two ranges.  */
  if (n1->start < n2->start)
    return -1;

  if (n1->end > n2->end)
    return 1;

  /* N1 is wholly covered by N2:
       n2->start <= n1->start <= n2->end
       n2->start <= n1->end   <= n2->end.
     We adjust its range so that the gap detection code does not get confused.  */
  n1->start = n2->start;
  n1->end   = n2->end;
  assert (n1->start <= n1->end);
  return 0;
}

static bool
notes_end_file (annocheck_data * data)
{
  if (disabled)
    return true;

  einfo (VERBOSE, "%u notes found", num_saved_notes);

  /* Sort the saved notes.  */
  qsort (saved_notes, num_saved_notes, sizeof saved_notes[0], compare_range);

  /* Display the saved notes.  */
  uint i;
  ulong prev_start = 0, prev_end = 0;
  for (i = 0; i < num_saved_notes; i++)
    {
      local_note * note = saved_notes + i;

      /* Ignore zero length notes, except in object files, or in verbose mode.  */
      if (note->start == note->end && ! BE_VERBOSE && e_type != ET_REL)
	continue;

      if (note->start != prev_start || note->end != prev_end)
	{
	  einfo (INFO, "Range: %#lx .. %#lx", note->start, note->end);
	  prev_start = note->start;
	  prev_end = note->end;
	}

      einfo (PARTIAL, "  ");

      uint value = note->value;

      switch (note->data[0])
	{
	case GNU_BUILD_ATTRIBUTE_VERSION:
	  if (value == -1)
	    einfo (PARTIAL, "Version: %s\n", note->data + 1);
	  else
	    einfo (PARTIAL, "Version: %x (?)\n", value);
	  break;

	case GNU_BUILD_ATTRIBUTE_TOOL:
	  if (value == -1)
	    einfo (PARTIAL, "Tool: %s\n", note->data + 1);
	  else
	    einfo (PARTIAL, "Tool: %x (?)\n", value);
	  break;

	case GNU_BUILD_ATTRIBUTE_RELRO:
	  einfo (PARTIAL, "RELRO: %x (?)\n", value);
	  break;

	case GNU_BUILD_ATTRIBUTE_ABI:
	  if (value == -1)
	    einfo (PARTIAL, "ABI: %s\n", note->data + 1);
	  else
	    einfo (PARTIAL, "ABI: %x\n", value);
	  break;

	case GNU_BUILD_ATTRIBUTE_STACK_SIZE:
	  einfo (PARTIAL, "Stack Size: %x\n", value);
	  break;

	case GNU_BUILD_ATTRIBUTE_PIC:
	  /* Convert the pic value into a pass/fail result.  */
	  switch (value)
	    {
	    default: einfo (PARTIAL, "PIC: *unknown*\n"); break;
	    case 0:  einfo (PARTIAL, "PIC: none\n"); break;
	    case 1:
	    case 2:  einfo (PARTIAL, "PIC: -fpic\n"); break;
	    case 3:
	    case 4:  einfo (PARTIAL, "PIC: -fpie\n"); break;
	    }
	  break;

	case GNU_BUILD_ATTRIBUTE_STACK_PROT:
	  switch (value)
	    {
	    default: einfo (PARTIAL, "Stack Protection: *unknown*\n"); break;
	    case 0:  einfo (PARTIAL, "Stack Protection: None\n"); break;
	    case 1:  einfo (PARTIAL, "Stack Protection: Basic\n"); break;
	    case 4:  einfo (PARTIAL, "Stack Protection: Explicit\n"); break;
	    case 2:  einfo (PARTIAL, "Stack Protection: All\n"); break;
	    case 3:  einfo (PARTIAL, "Stack Protection: Strong\n"); break;
	    }
	  break;

	case GNU_BUILD_ATTRIBUTE_SHORT_ENUM:
	  switch (value)
	    {
	    case 1:  einfo (PARTIAL, "Short Enums: Used\n"); break;
	    case 0:  einfo (PARTIAL, "Short Enums: Not Used\n"); break;
	    default: einfo (PARTIAL, "Short Enums: *unknown*\n"); break;
	    }
	  break;

	case 'c':
	  if (streq (note->data, "cf_protection"))
	    {
	      einfo (PARTIAL, "Control Flow Protection: ");
	      switch (value)
		{
		default:
		  einfo (PARTIAL, "*unknown*\n"); break;
		case 4: 
		case 8:
		  einfo (PARTIAL, "Full\n"); break;
		case 2:
		case 6:
		  einfo (PARTIAL, "Branch\n"); break;
		case 3:
		case 7:
		  einfo (PARTIAL, "Return\n"); break;
		case 1:
		case 5:
		  einfo (PARTIAL, "None\n"); break;
		  break;
		}
	    }
	  else
	    einfo (PARTIAL, "Unknown: '%s', value %d\n", note->data, note->value);
	  break;

	case 'F':
	  if (streq (note->data, "FORTIFY"))
	    {
	      einfo (PARTIAL, "FORTIFY: ");
	      switch (value)
		{
		default:
		  einfo (PARTIAL, "*unknown*\n"); break;
		case 0:
		case 1:
		case 2:
		  einfo (PARTIAL, "%d\n", value); break;
		}
	    }
	  else
	    einfo (PARTIAL, "Unknown: '%s', value %d\n", note->data, note->value);
	  break;

	case 'G':
	  if (streq (note->data, "GOW"))
	    {
	      if (value == -1)
		einfo (PARTIAL, "Optimization: *unknown*\n");
	      else if (value & (1 << 13))
		einfo (PARTIAL, "Optimization: -Og\n");
	      else
		einfo (PARTIAL, "Optimization: -O%d\n",(value >> 9) & 3);
	      /* FIXME: Display G and W data...  */
	    }
	  else if (streq (note->data, "GLIBCXX_ASSERTIONS"))
	    {
	      einfo (PARTIAL, "GLIBCXX_ASSERTIONS: ");
	      switch (value)
		{
		case 0: einfo (PARTIAL, "Not defined\n"); break;
		case 1: einfo (PARTIAL, "Defined\n"); break;
		default: einfo (PARTIAL, "*unknown*\n"); break;
		}
	    }
	  else
	    einfo (PARTIAL, "Unknown: '%s', value %d", note->data, note->value);
	  break;

	case 's':
	  if (streq (note->data, "stack_clash"))
	    {
	      einfo (PARTIAL, "Stack Clash Protection: ");
	      switch (value)
		{
		case 0: einfo (PARTIAL, "Not enabled\n"); break;
		case 1: einfo (PARTIAL, "Enabled\n"); break;
		default: einfo (PARTIAL, "*unknown*\n"); break;
		}
	    }
	  else if (streq (note->data, "stack_realign"))
	    {
	      einfo (PARTIAL, "Stack Realign: ");
	      switch (value)
		{
		default: einfo (PARTIAL, "*unknown*\n"); break;
		case 0:  einfo (PARTIAL, "Not enabled\n"); break;
		case 1:  einfo (PARTIAL, "Enabled\n"); break;
		}
	    }
	  else
	    einfo (PARTIAL, "Unknown: '%s', value %d\n", note->data, note->value);
	  break;

	case 'o':
	  if (streq (note->data, "omit_frame_pointer"))
	    {
	      switch (value)
		{
		default: einfo (PARTIAL, "Omit Frame Pointer: *unknown*\n"); break;
		case 0:  einfo (PARTIAL, "Omit Frame Pointer: No\n"); break;
		case 1:  einfo (PARTIAL, "Omit Frame Pointer: Yes\n"); break;
		}
	    }
	  else
	    einfo (PARTIAL, "Unknown: '%s', value %d\n", note->data, note->value);
	  break;

	default:
	  einfo (PARTIAL, "Unknown: '%s', value %d\n", note->data, note->value);
	  break;
	}
    }

  /* Free up the notes.  */
  free (saved_notes);
  num_saved_notes = num_allocated_notes = 0;
  
  return true;
}

static bool
notes_process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
  if (streq (arg, "--enable-notes"))
    disabled = false;

  else if (streq (arg, "--disable-notes"))
    disabled = true;

  else
    return false;

  return true;
}

static void
notes_usage (void)
{
  einfo (INFO, "Displays the annobin notes in the input files");
  einfo (INFO, " NOTE: This tool is disabled by default.  To enable it use: --enable-notes");
  einfo (INFO, " Use --disable-notes to restore the default behaviour");
  einfo (INFO, " Use --verbose to increase the amount of information displayed");
}

static void
notes_version (void)
{
  einfo (INFO, "Version 1.0");
}

struct checker notes_checker = 
{
  "Notes",
  notes_start_file,
  notes_interesting_sec,
  notes_check_sec,
  NULL, /* interesting_seg */
  NULL, /* check_seg */
  notes_end_file,
  notes_process_arg,
  notes_usage,
  notes_version,
  NULL, /* start_scan */
  NULL, /* end_scan */
  NULL /* internal */
};

static __attribute__((constructor)) void
notes_register_checker (void) 
{
  if (! annocheck_add_checker (& notes_checker, major_version))
    disabled = true;
}
