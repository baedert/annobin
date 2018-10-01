/* Detects the presence of retpoline instruction sequences in a binary.
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

static bool disabled = false;
static bool found = false;

static void
start_file (annocheck_data * data)
{
  found = false;
}

static bool
interesting_sec (annocheck_data *     data,
		 annocheck_section *  sec)
{
  if (disabled)
    return false;

  /* We want to scan code sections.  */
  if (sec->shdr.sh_type == SHT_PROGBITS
      && sec->shdr.sh_flags & SHF_EXECINSTR
      && sec->shdr.sh_size > 0)
    return true;

  /* We do not need any more information from the section, so there is no
     need to run the checker.  */
  return false;
}

static bool
check_sec (annocheck_data *     data,
	   annocheck_section *  sec)
{
  if (sec->data->d_size == 0)
    return true;

  /* Look for the binary sequence:
   	f3 90                	pause  
   	0f ae e8             	lfence.  */
#define SEQ_LENGTH 5
  static char sequence[SEQ_LENGTH] = { 0xf3, 0x90, 0x0f, 0xae, 0xe8 };
  size_t i;

  for (i = 0; i < sec->data->d_size - SEQ_LENGTH; i++)
    {
      /* FIXME: There are faster ways of doing this...  */
      if (memcmp (sec->data->d_buf + i, sequence, SEQ_LENGTH) == 0)
	{
	  einfo (VERBOSE2, "%s: sequence found in section %s", data->filename, sec->secname);
	  found = true;
	  break;
	}
    }

  return true;
}

static void
usage (void)
{
  einfo (INFO, "Detects the presence of retpoline sequences in binary files");
}

static void
version (void)
{
  einfo (INFO, "Version 1.0");
}

static bool
end_file (annocheck_data * data)
{
  if (disabled)
    return false;

  einfo (VERBOSE, "%s: %s", data->filename, found ? "uses retpolines" : "does not use retpolines");
  return found;
}

struct checker retpoline_checker = 
{
  "Retpoline Detector",
  start_file,
  interesting_sec,
  check_sec, 
  NULL, /* interesting_seg */
  NULL, /* check_seg */
  end_file,
  NULL, /* process_arg  */
  usage,
  version,
  NULL, /* start_scan */
  NULL, /* end_scan */
  NULL /* internal */
};

static __attribute__((constructor)) void
register_checker (void) 
{
  if (! annocheck_add_checker (& retpoline_checker, major_version))
    disabled = true;
}
