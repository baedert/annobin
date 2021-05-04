/* Monitors the time annocheck takes running its tools.
   Copyright (c) 2018 - 2019 Red Hat.

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
#include <time.h>

static bool disabled = true;

static unsigned int        num_files;
static unsigned long long  scan_time;
static clockid_t           clk_id;
static struct timespec     start_time;
static struct timespec     section_time;
static struct timespec     segment_time;
static bool                first_sec;
static bool                first_seg;
static enum res      
  {
    SEC, USEC, NSEC
  } resolution = USEC;

static bool
timing_start_file (annocheck_data * data)
{
  if (! disabled && clock_gettime (clk_id, & start_time) != 0)
    {
      einfo (SYS_WARN, "unable to get time at start of file processing");
      disabled = true;
      return false;
    }
  first_sec = true;
  first_seg = true;
  return true;
}

static bool
timing_interesting_sec (annocheck_data *     data,
		        annocheck_section *  sec)
{
  if (disabled || !first_sec)
    return false;

  first_sec = false;

  if (clock_gettime (clk_id, & section_time) != 0)
    einfo (SYS_WARN, "unable to get time at start of section scan");

  /* We do not need any more information from the section, so there is no
     need to run the checker.  */
  return false;
}

static bool
timing_interesting_seg (annocheck_data *     data,
			annocheck_segment *  seg)
{
  if (!disabled && first_seg)
    {
      if (clock_gettime (clk_id, & segment_time) != 0)
	einfo (SYS_WARN, "unable to get time at start of segment scan");
      first_seg = false;
    }

  /* We do not need any more information from the segment, so there is no
     need to run the checker.  */
  return false;
}

static unsigned long long int
time_diff (struct timespec * end, struct timespec * start)
{
  /* FIXME: Check for end < start ? */
  if (end->tv_nsec >= start->tv_nsec)
    return ((end->tv_sec - start->tv_sec) * 1000000) + (end->tv_nsec - start->tv_nsec);
  else
    return ((end->tv_sec - start->tv_sec) * 1000000) - (end->tv_nsec - start->tv_nsec);
}

static const char *
time_print (unsigned long long t)
{
  static char buffer[64];

  switch (resolution)
    {
    case SEC:  sprintf (buffer, "%llu seconds", t / (1000 * 1000)); break;
    case USEC: sprintf (buffer, "%llu microseconds", t / 1000); break;
    case NSEC: sprintf (buffer, "%llu nanoseconds", t); break;
    }

  return buffer;
}

static bool
timing_end_file (annocheck_data * data)
{
  if (disabled)
    return true;

  struct timespec end_time;

  if (clock_gettime (clk_id, & end_time) != 0)
    {
      einfo (SYS_WARN, "unable to get time at end of file scan");
      return false;
    }

  einfo (INFO, "%s: total time %s, ",
	 data->filename, time_print (time_diff (& end_time, & start_time)));  
  einfo (PARTIAL, "section scan: %s, ", time_print (time_diff (& segment_time, & section_time)));
  einfo (PARTIAL, "segment scan: %s ", time_print (time_diff (& end_time, & segment_time)));
  einfo (PARTIAL, "\n");

  num_files ++;
  scan_time += time_diff (& end_time, & start_time);
  return true;
}

/* This function is needed so that a data transfer file will be created.  */

static void
timing_start_scan (uint level, const char * datafile)
{
  if (disabled)
    return;

  num_files = 0;
  scan_time = 0;
  clk_id = CLOCK_REALTIME;

  if (0)
    ;
#ifdef CLOCK_MONOTONIC
  else if (clock_getres (CLOCK_MONOTONIC, NULL) == 0)
    clk_id = CLOCK_MONOTONIC;
#endif
#ifdef CLOCK_PROCESS_CPUTIME_ID
  else if (clock_getres (CLOCK_PROCESS_CPUTIME_ID, NULL) == 0)
    clk_id = CLOCK_PROCESS_CPUTIME_ID;
#endif
  /* FIXME: Try other clocks ?  */
}

static void
timing_end_scan (uint level, const char * datafile)
{
  if (disabled)
    return;

  FILE * f = fopen (datafile, "r");
  if (f != NULL)
    {
      unsigned int        num = 0;
      unsigned long long  time_taken = 0;
      
      einfo (VERBOSE2, "Loading recursed timing data from %s", datafile);

      if (fscanf (f, "%x %llx\n", & num, & time_taken) != 2)
	einfo (WARN, "unable to parse the contents of %s", datafile);

      num_files += num;
      scan_time += time_taken;
      fclose (f);
    }

  if (level == 0)
    {
      einfo (INFO, "%u files processed in %s", num_files, time_print (scan_time));
	     
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

      fprintf (f, "%x %llx\n", num_files, scan_time);
      fclose (f);
    }
}

static bool
timing_process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
  if (streq (arg, "--enable-timing"))
    disabled = false;

  else if (streq (arg, "--disable-timing"))
    disabled = true;

  else if (streq (arg, "--nsec"))
    resolution = NSEC;

  else if (streq (arg, "--usec"))
    resolution = USEC;
  
  else if (streq (arg, "--sec"))
    resolution = SEC;

  else
    return false;

  return true;
}

static void
timing_usage (void)
{
  einfo (INFO, "Reports the time annocheck's tool take to work");
  einfo (INFO, " NOTE: This tool is disabled by default.  To enable it use: --enable-timing");
  einfo (INFO, " Use --disable-timing to restore the default behaviour");
  einfo (INFO, " The resolution of the times reported can be set by the following options:");
}

static void
timing_version (void)
{
  einfo (INFO, "Version 1.0");
}

struct checker timing_checker = 
{
  "Timing",
  timing_start_file,
  timing_interesting_sec,
  NULL, /* check_sec */
  timing_interesting_seg,
  NULL, /* check_seg */
  timing_end_file,
  timing_process_arg,
  timing_usage,
  timing_version,
  timing_start_scan,
  timing_end_scan,
  NULL /* internal */
};

static __attribute__((constructor)) void
timing_register_checker (void) 
{
  if (! annocheck_add_checker (& timing_checker, ANNOBIN_VERSION / 100))
    disabled = true;
}
