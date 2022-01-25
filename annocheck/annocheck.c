/* annocheck - A tool for checking security features of binares.
   Copyright (c) 2018 - 2022 Red Hat.
   Created by Nick Clifton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "annobin-global.h"
#include "annocheck.h"
#include "config.h"
#include <limits.h>
#include <rpm/rpmlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <elfutils/libdwelf.h>
#include <elfutils/libdwfl.h>
#ifndef LIBANNOCHECK
#if HAVE_LIBDEBUGINFOD
#include <elfutils/debuginfod.h>
#endif
#endif

/* Prefix used to isolate annobin symbols from program symbols.  */
#define ANNOBIN_SYMBOL_PREFIX ".annobin_"

/* -1: silent, 0: normal, 1: verbose, 2: very verbose.  */
ulong         verbosity = 0;

enum ignore_enum
  {
    do_not_ignore = 0,
    ignore_not_set,
    do_ignore
  };

static ulong         	num_files = 0;
static ulong            num_allocated_files = 0;
static const char **    files;
static const char *     progname;
static enum ignore_enum ignore_unknown = ignore_not_set;
#ifndef LIBANNOCHECK
static char *           prefix = "";
#endif
static const char *     debug_path = NULL;
static const char *     debug_file = NULL;
#ifndef LIBANNOCHECK
static const char *     full_progname;
static uint             level = 0;
static char *           saved_args = NULL;
static const char *     debug_rpm = NULL;
static const char *     debug_rpm_dir = NULL;
static const char *     tmpdir = NULL;
#endif

#if HAVE_LIBDEBUGINFOD && ! defined LIBANNOCHECK
static bool             use_debuginfod = true;
#endif

static checker *        first_checker = NULL;
static checker *        first_sec_checker = NULL;
static checker *        first_seg_checker = NULL;

typedef struct checker_internal
{
  /* True if this checker should be skipped for this file.  */
  bool             skip;

  /* Pointer to the next section checker.  */
  struct checker * next_sec;

  /* Pointer to the next segment checker.  */
  struct checker * next_seg;

  /* Pointer to the next checker.  */
  struct checker * next;

  /* Name of the datafile used to share data with other iterations.  */
  const char *     datafile;

} checker_internal;
  
/* -------------------------------------------------------------------- */

#define COMPONENT_NAME_DEPTH 4
static const char * component_names[COMPONENT_NAME_DEPTH] = {[0] = "annocheck"};
static unsigned int component_name_index = 0;
#define CURRENT_COMPONENT_NAME component_names[component_name_index]

static void
push_component (checker * tool)
{
  ++ component_name_index;
  if (component_name_index >= COMPONENT_NAME_DEPTH)
    {
      --component_name_index;
      einfo (WARN, "Out of component name stack");
    }
  else
    component_names[component_name_index] = tool->name;
}

static void
pop_component (void)
{
  if (component_name_index > 0)
    -- component_name_index;
  else
    einfo (WARN, "Empty component name stack");
}

/* -------------------------------------------------------------------- */
/* Print a message on stdout or stderr.  Returns FALSE (for error
   messages) so that it can be used as a terminator in boolean functions.  */

bool
einfo (einfo_type type, const char * format, ...)
{
#ifdef LIBANNOCHECK
  return type == VERBOSE || type == VERBOSE2 || type == INFO || type == PARTIAL;
#else
  
  FILE *        file;
  const char *  pref = NULL;
  va_list       args;
  bool          res = false;

  switch (type)
    {
    case WARN:
    case SYS_WARN:
      pref = "Warning";
      file = stderr;
      break;
    case ERROR:
    case SYS_ERROR:
      pref = "Error";
      file = stderr;
      break;
    case FAIL:
      pref = "Internal Failure";
      file = stderr;
      break;
    case VERBOSE2:
    case VERBOSE:
      file = stdout;
      res  = true;
      break;
    case INFO:
      file = stdout;
      res  = true;
      break;
    case PARTIAL:
      file = stdout;
      res  = true;
      break;
    default:
      fprintf (stderr, "ICE: Unknown einfo type %x\n", type);
      exit (-1);
    }

  if (verbosity == -1UL
      || (type == VERBOSE && verbosity < 1)
      || (type == VERBOSE2 && verbosity < 2))
    return res;

  fflush (stderr);
  fflush (stdout);

  if (type != PARTIAL)
    fprintf (file, "%s: ", CURRENT_COMPONENT_NAME);

  const char *  do_newline;
  char          c;
  size_t        len = strlen (format);
  if (len < 1)
    {
      fprintf (stderr, "ICE: einfo called without a valid format string\n");
      exit (-1);
    }
  c = format[len - 1];
  if (c == '\n' || c == ' ')
    do_newline = "";
  else if (c == '.' || c == ':')
    do_newline = "\n";
  else
    do_newline = ".\n";

  if (pref)
    fprintf (file, "%s: ", pref);

  if (!PARTIAL && prefix[0])
    fprintf (file, "%s ", prefix);

  va_start (args, format);
  vfprintf (file, format, args);
  va_end (args);

  if (type == SYS_WARN || type == SYS_ERROR)
    fprintf (file, ": system error: %s", strerror (errno));

  if (type != PARTIAL)
    fprintf (file, "%s", do_newline);
  return res;
#endif
}

/* -------------------------------------------------------------------- */

void
add_file (const char * filename)
{
  if (num_files == num_allocated_files)
    {
      num_allocated_files += 128;
      files = xrealloc (files, num_allocated_files * sizeof (char *));
    }

  files[num_files ++] = filename;
}

/* -------------------------------------------------------------------- */

/* Utility function to walk over a note section calling FUNC
   on each note.  PTR is passed to FUNC along with a pointer to the note.
   If FUNC returns false the walk is terminated.
   Returns FALSE if the walk could not be executed.  */

bool
annocheck_walk_notes (annocheck_data * data, annocheck_section * sec, note_walker func, void * ptr)
{
  assert (data != NULL && sec != NULL && func != NULL);

  if (sec->shdr.sh_type != SHT_NOTE
      || sec->data == NULL
      || sec->data->d_size == 0)
    return false;

  size_t offset = 0;

  GElf_Nhdr  note;
  size_t     name_offset;
  size_t     data_offset;
  
  while ((offset = gelf_getnote (sec->data, offset, & note, & name_offset, & data_offset)) != 0)
    if (! func (data, sec, & note, name_offset, data_offset, ptr))
      break;

  return true;
}

/* Read in the section header for SECTION.  */

static bool
read_section_header (annocheck_data * data, Elf_Scn * section, Elf64_Shdr * s64hdr)
{
  if (data == NULL || section == NULL || s64hdr == NULL)
    return false;

  if (data->is_32bit)
    {
      Elf32_Shdr * shdr = elf32_getshdr (section);

      if (shdr == NULL)
	return false;

      s64hdr->sh_name = shdr->sh_name;
      s64hdr->sh_type = shdr->sh_type;
      s64hdr->sh_flags = shdr->sh_flags;
      s64hdr->sh_addr = shdr->sh_addr;
      s64hdr->sh_offset = shdr->sh_offset;
      s64hdr->sh_size = shdr->sh_size;
      s64hdr->sh_link = shdr->sh_link;
      s64hdr->sh_info = shdr->sh_info;
      s64hdr->sh_addralign = shdr->sh_addralign;
      s64hdr->sh_entsize = shdr->sh_entsize;
    }
  else
    {
      Elf64_Shdr * shdr = elf64_getshdr (section);

      if (shdr == NULL)
	return false;
      memcpy (s64hdr, shdr, sizeof * s64hdr);
    }

  return true;
}
  
/* -------------------------------------------------------------------- */

static bool
run_checkers (const char * filename, int fd, Elf * elf)
{
  annocheck_data data;

  memset (& data, 0, sizeof data);
  data.full_filename = filename;
  data.filename = lbasename (filename);
  data.fd = fd;
  data.dwarf_fd = -1;
  data.elf = elf;
  data.is_32bit = gelf_getclass (elf) == ELFCLASS32;

  checker * tool;

  /* Call the checker start functions.  */
  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    {
      if (tool->start_file)
	{
	  push_component (tool);
	  ((checker_internal *)(tool->internal))->skip = ! tool->start_file (& data);
	  pop_component ();
	}
      else
	((checker_internal *)(tool->internal))->skip = false;
    }

  bool ret = true;  

  if (first_sec_checker != NULL)
    {
      size_t shstrndx;

      if (elf_getshdrstrndx (elf, & shstrndx) < 0)
	return einfo (ERROR, "%s: Unable to locate string section", filename);
	      
      Elf_Scn * scn = NULL;

      while ((scn = elf_nextscn (elf, scn)) != NULL)
	{
	  annocheck_section  sec;

	  memset (& sec, 0, sizeof sec);

	  sec.scn = scn;
	  if (! read_section_header (& data, scn, & sec.shdr))
	    continue;

	  sec.secname = elf_strptr (elf, shstrndx, sec.shdr.sh_name);	  
	  if (sec.secname == NULL)
	    continue;

	  /* Note - do not skip empty sections, they may still be interesting to some tools.
	     If a tool is not interested in an empty section, it can always determine this
	     in its interesting_sec() function.  */

	  /* Walk the checkers, asking each in turn if they are interested in this section.  */
	  for (tool = first_sec_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next_sec)
	    {
	      if (((checker_internal *)(tool->internal))->skip || tool->interesting_sec == NULL)
		continue;

	      push_component (tool);

	      if (tool->interesting_sec (& data, & sec))
		{
		  /* Delay loading the section contents until a checker expresses interest.  */
		  if (sec.data == NULL)
		    {
		      sec.data = elf_getdata (scn, NULL);
		      if (sec.data == NULL)
			ret = einfo (ERROR, "Failed to read in section %s", sec.secname);
		    }

		  if (sec.data != NULL)
		    {
		      einfo (VERBOSE2, "is interested in section %s", sec.secname);

		      assert (tool->check_sec != NULL);
		      ret &= tool->check_sec (& data, & sec);
		    }
		}

	      pop_component ();
	    }
	}
    }

  if (first_seg_checker != NULL)
    {
      size_t phnum, cnt;

      elf_getphdrnum (elf, & phnum);

      for (cnt = 0; cnt < phnum; ++cnt)
	{
	  GElf_Phdr   mem;
	  annocheck_segment seg;

	  memset (& seg, 0, sizeof seg);

	  seg.phdr = gelf_getphdr (elf, cnt, & mem);
	  seg.number = cnt;

	  if (seg.phdr == NULL)
	    /* Fuzzzing can produce segments like this.  */
	    continue;
			       
	  for (tool = first_seg_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next_seg)
	    {
	      if (((checker_internal *)(tool->internal))->skip || tool->interesting_seg == NULL)
		continue;

	      push_component (tool);

	      if (tool->interesting_seg (& data, & seg))
		{
		  /* Delay loading the contents of the segment until they are actually needed.  */
		  if (seg.data == NULL)
		    seg.data = elf_getdata_rawchunk (elf, seg.phdr->p_offset,
						     seg.phdr->p_filesz, ELF_T_BYTE);

		  assert (tool->check_seg != NULL);
		  ret &= tool->check_seg (& data, & seg);
		}

	      pop_component ();
	    }
	}
    }

  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    if (! ((checker_internal *)(tool->internal))->skip && tool->end_file)
      {
	push_component (tool);
	ret &= tool->end_file (& data);
	pop_component ();
      }

  if (data.dwarf_fd != -1 && data.dwarf_fd != data.fd)
    {
      close (data.dwarf_fd);
      data.dwarf_fd = -1; /* Paranoia.  */
    }

  return ret;
}

#ifndef LIBANNOCHECK
/* Like process_rpm_file, except that the rpm is just
   extracted and then left untouched.  Returns the name
   of the directory holding the rpm contents.  */

static const char *
extract_rpm_file (const char * filename)
{
  static char dirname[32];

  if (debug_rpm_dir != NULL)
    return debug_rpm_dir;

  dirname[0] = 0;
  strcpy (dirname, "annocheck.debuginfo.XXXXXX");
  if (mkdtemp (dirname) == NULL)
    {
      einfo (ERROR, "Failed to create temporary directory for debuginfo extraction: %s", filename);
      return NULL;
    }

  einfo (VERBOSE2, "Created temporary directory for debuginfo extraction: %s", dirname);

  char * fname;
  char * command;
  char * cwd = getcwd (NULL, 0);

  /* If filename is a relative path, convert it to an absolute one
     so that it can be found once we change into the temporary directory.  */
  if (filename[0] != '/')
    fname = concat (cwd, "/", filename, NULL);
  else
    /* This is just so that we can safely call free(fname) at the end.  */
    fname = concat (filename, NULL);

  if (access (fname, F_OK) == -1) 
    {
      einfo (SYS_ERROR, "Error reading rpm file file %s", fname);
      free (fname);
      return NULL;
    }

  command = concat (/* Change into the temporary directory.  */
		    "cd ", dirname,
		    /* Convert the rpm to cpio format.  */
		    " && rpm2cpio \"", fname, "\"",
		    /* Pipe the output into cpio in order to extract the files.  */
		    " | cpio -dium --quiet",
		    /* Then move out of the directory.  */
		    " && cd ..",
		    NULL);

  einfo (VERBOSE2, "Running rpm extractor command sequence: %s", command);
  fflush (stdin);
  
  if (system (command))
    {
      einfo (WARN, "Failed to extract rpm file: %s", filename);
      return NULL;
    }

  free (command);
  free (cwd);
  free (fname);

  einfo (VERBOSE2, "Extraction successful");
  return debug_rpm_dir = dirname;
}

#endif /* not LIBANNOCHECK */

#define TRY_DEBUG(format,args...)					\
  do									\
    {									\
      if (debugfile == NULL) return false; /* Pacify Address Sanitizer */\
      sprintf (debugfile, format, args);				\
      einfo (VERBOSE2, "%s:  try: %s", data->filename, debugfile);	\
      if ((fd = open (debugfile, O_RDONLY)) != -1)			\
	goto found;							\
    }									\
  while (0)

static bool
follow_debuglink (annocheck_data * data)
{
  char *  canon_dir = NULL;
  char *  debugfile = NULL;
  int     fd;

  if (data->filename == NULL)
    return false;

  /* Initialise the dwarf specific fields of the data structure.  */
  data->dwarf = NULL;
  if (data->dwarf_fd != -1 && data->dwarf_fd != data->fd)
    close (data->dwarf_fd);
  data->dwarf_fd = -1;
  data->dwarf_filename = NULL;
  
  /* First try the build-id method.  */
  ssize_t       build_id_len;
  const void *  build_id_ptr;

  einfo (VERBOSE2, "%s: Attempting to locate separate debuginfo file", data->filename);

  if (debug_file)
    {
      debugfile = (char *) xmalloc (strlen (debug_file) + 2);
      TRY_DEBUG ("%s", debug_file);
      free (debugfile);
    }

  build_id_len = dwelf_elf_gnu_build_id (data->elf, & build_id_ptr);
  if (build_id_len > 0)
    {
      /* Compute the path to the debuginfo from the build id.
	 Since we know that we are running on a Fedora/RHEL
	 system we can just check the standard Fedora location:
	 
	  /usr/lib/debug/.build-id/NN/NN+NN.debug
	  
	where NNNN+NN is the build-id value as a hexadecimal
	string.  */

      const char *     path = NULL;
      const char *     leadin = "/usr/lib/debug/.build-id";
      unsigned char *  d = (unsigned char *) build_id_ptr;
      ssize_t          len = build_id_len;
      char             build_id_dir[3];
      char *           build_id_name;
      char *           n;

      einfo (VERBOSE2, "%s: Testing possibilities based upon the build-id", data->filename);

#ifndef LIBANNOCHECK      
      if (debug_rpm)
	/* If the user has told us an rpm file that contains
	   debug information then extract it and use it.  */
	path = extract_rpm_file (debug_rpm);
      else
	{
#endif
	  if (debug_path)
	    path = debug_path;
#ifndef LIBANNOCHECK
	}
#endif

      if (path == NULL)
	path = "";
      
      debugfile = xmalloc (strlen (leadin)
			   + strlen (path)
			   + len * 2
			   + strlen (".debug") + 6);
      
      sprintf (build_id_dir, "%02x", * d++);
      len --;
      build_id_name = n = xmalloc (len * 2 + 1);
      while (len --)
	n += sprintf (n, "%02x", *d++);      

      einfo (VERBOSE2, "%s: build_id_len: %lu, name: %s", data->filename,
	     (unsigned long) build_id_len, build_id_name);

      if (* path)
	{
	  /* If the user has supplied a directory to search then this might be
	     an unpacked debuginfo rpm.  So try the following possibilities:

	     <path>/NNNNN.debug
	     <path>/NN/NNNNN.debug
	     <path>/.build-id/NN/NNNN.debug
	     <path>/usr/lib/debug/.build-id/NN/NNNNN.debug */

          TRY_DEBUG ("%s/%s.debug", path, build_id_name);
          TRY_DEBUG ("%s/%s/%s.debug", path, build_id_dir, build_id_name);
          TRY_DEBUG ("%s/.build-id/%s/%s.debug", path, build_id_dir, build_id_name);
          TRY_DEBUG ("%s/%s/%s/%s.debug", path, leadin + 1, build_id_dir, build_id_name);
	}

      TRY_DEBUG ("%s/%s/%s.debug", leadin, build_id_dir, build_id_name);

      free (debugfile);
      einfo (VERBOSE2, "%s: Could not find separate debuginfo file based on build-id", data->filename);
    }

  /* Now try using a .gnu.debuglink section.  */
  GElf_Word     crc;
  const char *  link;

  if ((link = dwelf_elf_gnu_debuglink (data->elf, & crc)) == NULL)
    {
      einfo (VERBOSE2, "%s: Could not find separate debug file", data->filename);
      return NULL;
    }

  einfo (VERBOSE2, "%s: Testing possibilities based upon debuglink section(s)", data->filename);

  size_t canon_dirlen;

  /* Attempt to locate the separate file.  */
  canon_dir = lrealpath (data->filename);
  
  for (canon_dirlen = strlen (canon_dir); canon_dirlen > 0; canon_dirlen--)
    if (canon_dir[canon_dirlen - 1] == '/')
      break;
  canon_dir[canon_dirlen] = '\0';

#define DEBUGDIR_1 "/lib/debug"
#define DEBUGDIR_2 "/usr/lib/debug"
#define DEBUGDIR_3 "/usr/lib/debug/usr"
#define DEBUGDIR_4 "/usr/lib/debug/usr/lib64"

  debugfile = (char *) xmalloc (strlen (DEBUGDIR_1) + 1
				+ strlen (DEBUGDIR_2)
				+ strlen (DEBUGDIR_3)
				+ strlen (DEBUGDIR_4)
				+ (debug_path ? strlen (debug_path) : 1)
				+ canon_dirlen
				+ strlen (".debug/")
				+ strlen (link)
				+ 1);

  /* If we have been provided with a debug directory, try that first.  */
  if (debug_path)
    TRY_DEBUG ("%s/%s", debug_path, link);

#ifndef LIBANNOCHECK
  /* If we have been pointed at a debuginfo rpm then try that next.  */
  if (debug_rpm)
    {
      const char * dir = extract_rpm_file (debug_rpm);
      if (dir != NULL)
	{
	  TRY_DEBUG ("./%s/%s", dir, link);
	  TRY_DEBUG ("./%s%s/%s", dir, DEBUGDIR_1, link);
	  TRY_DEBUG ("./%s%s/%s", dir, DEBUGDIR_2, link);
	  TRY_DEBUG ("./%s%s/%s", dir, DEBUGDIR_3, link);
	  TRY_DEBUG ("./%s%s/%s", dir, DEBUGDIR_4, link);
	}
    }
#endif
  
  /* next try in the current directory.  */
  TRY_DEBUG ("./%s", link);

  /* Then try in a subdirectory called .debug.  */
  TRY_DEBUG ("./.debug/%s", link);

  /* Then try in the same directory as the original file.  */
  TRY_DEBUG ("%s%s", canon_dir, link);

  /* And the .debug subdirectory of that directory.  */
  TRY_DEBUG ("%s.debug/%s", canon_dir, link);

  /* Try the first extra debug file root.  */
  TRY_DEBUG ("%s/%s", DEBUGDIR_2, link);

  /* Try the first extra debug file root, with directory extensions.  */
  TRY_DEBUG ("%s%s%s", DEBUGDIR_2, canon_dir, link);

  /* Try the second extra debug file root.  */
  TRY_DEBUG ("%s/%s", DEBUGDIR_3, link);

  /* Try the fourth extra debug file root.  */
  TRY_DEBUG ("%s/%s", DEBUGDIR_4, link);

  /* Then try in the global debugfile directory.  */
  TRY_DEBUG ("%s/%s", DEBUGDIR_1, link);

  /* Then try in the global debugfile directory, with directory extensions.  */
  TRY_DEBUG ("%s%s%s", DEBUGDIR_1, canon_dir, link);

  /* Try the first extra debug file root, with directory extensions.  */
  TRY_DEBUG ("%s%s%s", DEBUGDIR_2, canon_dir, link);

  /* FIMXE: This is a workaround for a bug in the Fedora packaging
     system.  It is possible for the debuginfo files to be out of
     sync with their corresponding binary files.  Eg:
          ld-2.29.1-23.fc28
       vs ld-2.29.1-22.fc28.debug_info.
     So check for earlier versions of the debuginfo file in the directory
     where it is known that Fedora stores its debug files...  */
  char * dash = strrchr (link, '-');
  if (dash)
    {
      char * end;
      unsigned long revision = strtoul (dash + 1, & end, 10);

      while (revision > 1)
	{
	  --revision;

	  TRY_DEBUG ("%s%s%.*s%lu%s", DEBUGDIR_2, canon_dir, (int) (dash - link) + 1, link, revision, end);
	}
    }

#ifndef LIBANNOCHECK
#if HAVE_LIBDEBUGINFOD
  if (! use_debuginfod)
    ;
  else if (build_id_len > 0)
    {
      debuginfod_client *client = debuginfod_begin ();

      if (client != NULL)
        {
	  TRY_DEBUG ("DEBUGINFOD_URLS=%s", getenv (DEBUGINFOD_URLS_ENV_VAR) ?: "" );
	  
          /* If the debug file is successfully downloaded, debugfile will be
             set to the path of the local copy.  */
          fd = debuginfod_find_debuginfo (client, build_id_ptr, build_id_len, & debugfile);

          debuginfod_end (client);

          if (fd >= 0)
            {
              /* Ensure file is read-only.  */
              close (fd);
              if ((fd = open (debugfile, O_RDONLY)) != -1)
                goto found;
            }
        }
      else
	einfo (VERBOSE2, "%s: unable to initialise debuginfod client", data->filename);
    }
  else
    einfo (VERBOSE2, "%s: no build-id found, so cannot query debuginfod service", data->filename);
#else
  einfo (VERBOSE2, "%s: support for debuginfod not built into annocheck", data->filename);
#endif /* HAVE_LIBDEBUGINFOD */
#endif /* not LIBANNOCHECK */

  /* Failed to find the file.  */
  einfo (VERBOSE2, "%s: warn: Could not find separate debug file: %s", data->filename, link);
  
  free (canon_dir);
  free (debugfile);
  return false;

 found:
  /* FIXME: We should verify the CRC value.  */

  free (canon_dir);

  /* Now open the file...  */
  Dwarf * separate_debug_file = dwarf_begin (fd, DWARF_C_READ);
  if (separate_debug_file == NULL)
    {
      int err = dwarf_errno ();

      if (err)
	einfo (VERBOSE, "%s: warn: Failed to parse separate debug file '%s', (%s)",
	       data->filename, debugfile, dwarf_errmsg (err));
      else
	einfo (VERBOSE, "%s: warn: Failed to parse separate debug file '%s', (no error message available)",
	       data->filename, debugfile);	
      
      free (debugfile);
      return false;
    }

  einfo (VERBOSE2, "%s: Opened separate debug file: %s", data->filename, debugfile);
  data->dwarf_fd = fd;
  data->dwarf_filename = debugfile;
  data->dwarf_searched = false;
  data->dwarf = separate_debug_file;
  return true;
}

/* -------------------------------------------------------------------- */

static bool
scan_dwarf (annocheck_data * data, Dwarf * dwarf, dwarf_walker func, void * ptr)
{
  Dwarf_Off  cuoffset;
  Dwarf_Off  ncuoffset = 0;
  size_t     hsize;

  while (dwarf_nextcu (dwarf, cuoffset = ncuoffset, & ncuoffset, & hsize, NULL, NULL, NULL) == 0)
    {
      Dwarf_Off cudieoff = cuoffset + hsize;
      Dwarf_Die cudie;

      if (dwarf_offdie (dwarf, cudieoff, & cudie) == NULL)
	{
	  einfo (ERROR, "%s: Empty CU", data->filename);
	  continue;
	}

      if (! func (data, dwarf, & cudie, ptr))
	return false;
    }

  return true;
}

/* Utility function to walk over the DWARF debug information in DATA calling FUNC
   on each DIE.  PTR is passed to FUNC along with a pointer to the DIE.
   If FUNC returns false the walk is terminated.
   Returns FALSE if the walk could not be executed.  */

bool
annocheck_walk_dwarf (annocheck_data * data, dwarf_walker func, void * ptr)
{
  Dwarf * dwarf;

  if (! data->dwarf_searched)
    {
      dwarf = dwarf_begin (data->fd, DWARF_C_READ);

      if (dwarf != NULL)
	{
	  data->dwarf = dwarf;
	  data->dwarf_fd = data->fd;
	  data->dwarf_filename = data->filename;
	  data->dwarf_searched = true;
	}
      else if (! follow_debuglink (data))
	return einfo (VERBOSE2, "%s: Does not contain or link to any DWARF information", data->filename);
    }

  if ((dwarf = data->dwarf) == NULL)
    return true;

  (void) scan_dwarf (data, dwarf, func, ptr);

  /* We used to call dwarf_getalt() if the scan failed to find anything.
     But that was a waste of time.  libdw will automatically load any
     alternate debug info files pointed to by sections in the binary.  */

  /* We do not close the dwarf handle as we will probably want to use it again.  */
  return true;
}

/* -------------------------------------------------------------------- */

static bool
ends_with (const char * string, const char * ending, const size_t end_len)
{
  size_t len;

  return (string != NULL
	  && ending != NULL
	  && end_len > 0
	  && (len = strlen (string)) > end_len
	  && streq (string + (len - end_len), ending));
}

bool
annocheck_find_symbol_by_name (annocheck_data * data, const char * name,
			       ulong * value_return, uint * section_return)
{
  /* Search for symbol sections.  */
  Elf_Scn *  sym_sec = NULL;

  while ((sym_sec = elf_nextscn (data->elf, sym_sec)) != NULL)
    {
      Elf64_Shdr sym_shdr;

      if (! read_section_header (data, sym_sec, & sym_shdr))
	continue;

      if ((sym_shdr.sh_type != SHT_SYMTAB) && (sym_shdr.sh_type != SHT_DYNSYM))
	continue;

      Elf_Data *  sym_data;

      if ((sym_data = elf_getdata (sym_sec, NULL)) == NULL)
	{
	  einfo (VERBOSE2, "Unable to load symbol section");
	  /* FIXME: Warn ??  */
	  continue;
	}

      GElf_Sym  sym;
      uint      symndx;

      for (symndx = 1; gelf_getsym (sym_data, symndx, & sym) != NULL; symndx++)
	{
	  const char * symname = elf_strptr (data->elf, sym_shdr.sh_link, sym.st_name);

	  if (streq (name, symname))
	    {
	      if (value_return != NULL)
		* value_return = sym.st_value;
	      if (section_return != NULL)
		* section_return = sym.st_shndx;
	      return true;
	    }
	}
    }

  return false;
}

typedef struct find_symbol_return
{
  const char * name;
  uint         type;
  ulong        distance;
} find_symbol_return;

static bool
find_symbol_in (Elf * elf, Elf_Scn * sym_sec, ulong start, ulong end, Elf64_Shdr * sym_hdr, bool prefer_func, find_symbol_return * data_return)
{
  Elf_Data * sym_data;

  if (data_return == NULL || sym_hdr == NULL)
    return false;

  if (sym_hdr->sh_entsize == 0)
    return false;

  if ((sym_data = elf_getdata (sym_sec, NULL)) == NULL)
    {
      einfo (VERBOSE2, "No symbol section data");
      return false;
    }

  uint          best_type = 0;
  const char *  best_name = NULL;
  uint          second_best_type = 0;
  const char *  second_best_name = NULL;
  ulong         best_distance_so_far = ULONG_MAX;
  ulong         second_best_distance = ULONG_MAX;
  GElf_Sym      sym;
  uint          symndx;

  for (symndx = 1; gelf_getsym (sym_data, symndx, & sym) != NULL; symndx++)
    {
      if (sym.st_value < start || sym.st_value >= end)
	continue;

      /* Skip annobin symbols.  */
      if (GELF_ST_TYPE (sym.st_info) == STT_NOTYPE
	  && GELF_ST_BIND (sym.st_info) == STB_LOCAL
	  && GELF_ST_VISIBILITY (sym.st_other) == STV_HIDDEN)
	continue;

      const char * name = elf_strptr (elf, sym_hdr->sh_link, sym.st_name);

      if (name == NULL || *name == 0)
	continue;

      if (ends_with (name, "_end", strlen ("_end")))
	continue;

      if (ends_with (name, ".end", strlen (".end")))
	continue;

      ulong  distance_from_start = sym.st_value - start;
      uint   type = GELF_ST_TYPE (sym.st_info);

      if (prefer_func && type != STT_FUNC && type != STT_GNU_IFUNC)
	{
	  if (distance_from_start > second_best_distance)
	    continue;
	  second_best_name = name;
	  second_best_type = type;
	  second_best_distance = distance_from_start;
	}
      else
	{
	  if (distance_from_start > best_distance_so_far)
	    continue;
	  best_name = name;
	  best_type = type;
	  best_distance_so_far = distance_from_start;
	}
    }

  if (symndx != sym_hdr->sh_size / sym_hdr->sh_entsize)
    /* Something went wrong with the loop.  */
    return false;

  if (best_name != NULL)
    {
      data_return->name = best_name;
      data_return->type = best_type;
      data_return->distance = best_distance_so_far;
      return true;
    }

  if (second_best_name != NULL)
    {
      data_return->name = second_best_name;
      data_return->type = second_best_type;
      data_return->distance = second_best_distance;
      return true;
    }

  return false;
}

typedef struct walker_info
{
  ulong                start;
  ulong                end;
  bool                 prefer_func;
  find_symbol_return * data_return;
} walker_info;

static bool
find_symbol_addr_using_dwarf (annocheck_data * data, Dwarf * dwarf, Dwarf_Die * die, void * ptr)
{
  assert (data != NULL && die != NULL && ptr != NULL);

  walker_info * info = (walker_info *) ptr;

  /* If we are examining a separate debuginfo file then
     it might have a symbol table that we can use.  */
  if (data->elf != dwarf_getelf (dwarf))
    {
      Elf_Scn *  sym_sec = NULL;
      Elf *      elf = dwarf_getelf (dwarf);

      while ((sym_sec = elf_nextscn (elf, sym_sec)) != NULL)
	{
	  Elf64_Shdr   sym_shdr;

	  if (! read_section_header (data, sym_sec, & sym_shdr))
	    continue;

	  if ((sym_shdr.sh_type == SHT_SYMTAB) || (sym_shdr.sh_type == SHT_DYNSYM))
	    {
	      if (find_symbol_in (elf, sym_sec, info->start, info->end, & sym_shdr, info->prefer_func, info->data_return))
		{
		  if (info->data_return->distance == 0)
		    return false; /* This means 'stop searching'.  */
		}
	    }
	}
    }

  /* If we found a name, even one not at START, then stop searching.
     The dwarf data whilst possibly providing a better match, will
     not provide any ELF symbol type information.  */
  if (info->data_return->name != NULL)
    return false;  /* This means 'stop searching'.  */

  size_t         nlines;
  Dwarf_Lines *  lines;

  if (dwarf_getsrclines (die, & lines, & nlines) != 0)
    {
      /* FIXME: We could report dwarf_errmsg() here.  */
      einfo (VERBOSE2, "Unable to retrieve a DWARF line table");
      return false;
    }

  if (lines != NULL && nlines > 0)
    {
      Dwarf_Line * line;
      size_t       indx = 1;
      ulong        best_distance_so_far = ULONG_MAX;
      const char * best_name = NULL;

      einfo (VERBOSE2, "Scanning %lu lines in the DWARF line table", (unsigned long) nlines);
      while ((line = dwarf_onesrcline (lines, indx)) != NULL)
	{
	  Dwarf_Addr addr;

	  dwarf_lineaddr (line, & addr);

	  if (addr >= info->start && addr < info->end)
	    {
	      ulong distance_from_start = addr - info->start;
	      if (distance_from_start < best_distance_so_far)
		{
		  best_distance_so_far = distance_from_start;
		  best_name = dwarf_linesrc (line, NULL, NULL);
		}
	    }
	  ++ indx;
	}

      if (best_name)
	{
	  info->data_return->name = best_name;
	  info->data_return->distance = best_distance_so_far;
	  info->data_return->type = 0; /* No ELF type data in DWARF...  */
	  return false; /* This means 'stop searching'.  */
	}
    }

  return true; /* This means 'continue searching'.  */
}

/* Return the name of a symbol most appropriate for address range START..END.
   Returns NULL if no symbol could be found.  */

const char *
annocheck_find_symbol_for_address_range (annocheck_data *     data,
					 annocheck_section *  sec,
					 ulong                start,
					 ulong                end,
					 bool                 prefer)
{
  return annocheck_get_symbol_name_and_type (data, sec, start, end, prefer, NULL);
}

/* Return the name of a symbol most appropriate for address START..END.
   Returns NULL if no symbol could be found.
   If a name is found, and the symbol's ELF type is available, return it in TYPE_RETURN.  */

const char *
annocheck_get_symbol_name_and_type (annocheck_data *     data,
				    annocheck_section *  sec,
				    ulong                start,
				    ulong                end,
				    bool                 prefer_func,
				    uint *               type_return)
{
  static const char * previous_result = NULL;
  static ulong        previous_start = 0;
  static ulong        previous_end = 0;
  static uint         previous_type = 0;

  Elf64_Shdr   sym_shdr;
  Elf_Scn *    sym_sec = NULL;

  if (type_return != NULL)
    * type_return = 0;

  if (start > end)
    return NULL;

  if (start == previous_start && end == previous_end)
    {
      if (type_return != NULL)
	* type_return = previous_type;
      return previous_result;
    }

  assert (data != NULL);

  previous_start = start;
  previous_end   = end;

  einfo (VERBOSE2, "Look for a symbol matching address %#lx..%#lx", start, end);

  find_symbol_return data_return;
  memset (& data_return, 0, sizeof data_return);

  /* If the provided section has a link then try this first.  */
  if (sec != NULL && sec->shdr.sh_link)
    {
      sym_sec = elf_getscn (data->elf, sec->shdr.sh_link);

      if (read_section_header (data, sym_sec, & sym_shdr))
	{
	  if (sym_shdr.sh_type == SHT_SYMTAB || sym_shdr.sh_type == SHT_DYNSYM)
	    {
	      if (find_symbol_in (data->elf, sym_sec, start, end, & sym_shdr, prefer_func, & data_return))
		{
		  if (data_return.distance == 0)
		    goto found;
		}
	    }
	}
    }

  /* Search for symbol sections.  */
  sym_sec = NULL;
  while ((sym_sec = elf_nextscn (data->elf, sym_sec)) != NULL)
    {
      if (! read_section_header (data, sym_sec, & sym_shdr))
	continue;

      if ((sym_shdr.sh_type == SHT_SYMTAB) || (sym_shdr.sh_type == SHT_DYNSYM))
	{
	  if (find_symbol_in (data->elf, sym_sec, start, end, & sym_shdr, prefer_func, & data_return))
	    {
	      if (data_return.distance == 0)
		goto found;
	    }
	}
    }

  /* Now check DWARF data for an address match.  */
  walker_info walker;
  walker.start = start;
  walker.end = end;
  walker.prefer_func = prefer_func;
  walker.data_return = & data_return;

  annocheck_walk_dwarf (data, find_symbol_addr_using_dwarf, & walker);

 found:
  if (type_return != NULL)
    {
      * type_return = data_return.type;
      previous_type = data_return.type;
    }
  else
    previous_type = 0;

  if (previous_result != NULL)
    {
      if (data_return.name != NULL
	  && streq (previous_result, data_return.name))
	return previous_result;
      free ((void *) previous_result);
    }

  if (data_return.name != NULL)
    previous_result = strdup (data_return.name);
  else
    previous_result = NULL;

  return previous_result;
}

/* -------------------------------------------------------------------- */

static bool process_elf (const char *, int, Elf *);

static bool
process_ar (const char * filename, int fd, Elf * elf)
{
  Elf *    subelf;
  Elf_Cmd  cmd = ELF_C_READ_MMAP;
  bool     ret = true;

  while ((subelf = elf_begin (fd, cmd, elf)) != NULL)
    {
      /* Get the header for this element.  */
      Elf_Arhdr * arhdr = elf_getarhdr (subelf);
      const char * fname = concat (filename, ":", arhdr->ar_name, NULL);

      /* Skip over the index entries.  */
      if (! streq (arhdr->ar_name, "/")
	  && ! streq (arhdr->ar_name, "//"))
	ret = process_elf (fname, fd, subelf);

      /* Get next archive element.  */
      cmd = elf_next (subelf);

      if (elf_end (subelf))
	return einfo (FAIL, "unable to close archive member %s", fname);

      free ((char *) fname);
    }

  return ret;
}

static bool
process_elf (const char * filename, int fd, Elf * elf)
{
  switch (elf_kind (elf))
    {
    case ELF_K_AR:  return process_ar (filename, fd, elf);
    case ELF_K_ELF: return run_checkers (filename, fd, elf);
    default:        break;
    }

  /* Try reading the magic number.  */
  char buf[4];
  if (read (fd, buf, 4) == 4)
    {
      const char llvm_magic[4] = { 0x42, 0x43, 0xc0, 0xde };
      /* Check for known magic values.  */
      if (memcmp (buf, llvm_magic, sizeof llvm_magic) == 0)
	return einfo (WARN, "%s is an LLVM bitcode file - should it be here ?", filename);
    }
  else einfo (VERBOSE, "%s: unable to read magic number", filename);

  if (ignore_unknown == do_ignore)
    return true;

  return einfo (WARN, "%s: is not an ELF format file", filename);
}

#ifndef LIBANNOCHECK
static const char *
itoa (uint level)
{
  switch (level)
    {
    case 0: return "0";
    case 1: return "1";
    case 2: return "2";
    case 3: return "3";
    default: return "4"; /* Can this ever be reached ?  */
    }
}

static bool
process_rpm_file (const char * filename)
{
  /* It turns out that the simplest/most portable way to handle an rpm is
     to use the rpm2cpio and cpio programs to unpack it for us...  */
  char dirname[32];

  strcpy (dirname, "annocheck.rpm.XXXXXX");
  if (mkdtemp (dirname) == NULL)
    return einfo (WARN, "Failed to create temporary directory for processing rpm: %s", filename);

  einfo (VERBOSE2, "Created temporary directory for rpm processing: %s", dirname);

  char * fname;
  char * pname;
  char * command;
  char * cwd = getcwd (NULL, 0);

  if (filename[0] != '/')
    fname = concat (cwd, "/", filename, NULL);
  else
    fname = concat (filename, NULL);

  if (full_progname == NULL || * full_progname == 0)
    pname = concat (cwd, "/", "libannocheck", NULL);
  else if (full_progname[0] != '/' && strchr (full_progname, '/'))
    pname = concat (cwd, "/", full_progname, NULL);
  else
    pname = concat (full_progname, NULL);

  command = concat (/* Change into the temporary directory.  */
		    "cd ", dirname,
		    /* Convert the rpm to cpio format.  */
		    " && rpm2cpio \"", fname, "\"",
		    /* Pipe the output into cpio in order to extract the files.  */
		    " | cpio -dium --quiet",
		    /* Run annocheck on the files in the directory, skipping unknown file types,
		       and prefixing the output with the rpm name.  */
		    " && ", pname, " --ignore-unknown ",
		    "--prefix \"", lbasename (filename), "\"",
		    /* Increment the recursion level.  */
		    " --level ", itoa (level + 1),
		    " --ignore-unknown",
#if HAVE_LIBDEBUGINFOD && !defined LIBANNOCHECK 
		    use_debuginfod ? "" : " --no-use-debuginfod",
#endif
		    /* Pass on the name of the temporary data directory, if created.  */
		    tmpdir == NULL ? "" : " --tmpdir ",
		    tmpdir == NULL ? "" : tmpdir,
		    /* Then all the other options that the user has supplied.  */
		    " ", saved_args ? saved_args : "",
		    " .",
		    NULL);

  einfo (VERBOSE2, "Running rpm extractor command sequence: %s", command);
  fflush (stdin);

  int result = system (command);
  if (result == -1 || result == 127)
    return einfo (WARN, "Failed to process rpm file: %s", filename);

  free (command);
  free (cwd);
  free (fname);
  free (pname);

  /* Delete the temporary directory.  */
  command = concat ("rm -fr ", dirname, NULL);
  if (system (command))
    einfo (WARN, "Failed to delete temporary directory: %s", dirname);
  free (command);

  einfo (VERBOSE2, "RPM processed successfully");
  return result == EXIT_SUCCESS;
}
#endif /* not LIBANNOCHECK */

static bool
process_file (const char * filename)
{
#ifndef LIBANNOCHECK
  size_t       len;
#endif
  struct stat  statbuf;
  int          res;

  /* Fast track ignoring of debuginfo files.
     FIXME: Maybe add other file extensions ?
     FIXME: Maybe check that the extension is at the end of the filename ?  */
  if (ignore_unknown != do_not_ignore && ends_with (filename, ".debug", 6))
    return true;

  res = lstat (filename, & statbuf);

  if (res == 0 && S_ISLNK (statbuf.st_mode))
    {
      switch (ignore_unknown)
	{
	case do_not_ignore:
	  return einfo (WARN, "'%s' is a symbolic link.  Run %s with -i to follow the link", filename, progname);

	case do_ignore:
	  /* If we are ignoring unknown files then ignore the link.
	     This is because the ignore option is usually only set when parsing rpm files,
	     and symbolic links in those files should be ignored.  */
	  return true;

	default:
	  /* Default behaviour is to follow the link.  */
	  res = stat (filename, & statbuf);
	  break;
	}
    }
  
  if (res < 0)
    {
      if (errno == ENOENT)
	{
	  if (lstat (filename, & statbuf) == 0
	      && S_ISLNK (statbuf.st_mode))
	    return einfo (WARN, "'%s': Could not follow link", filename);
	  else
	    return einfo (WARN, "'%s': No such file", filename);
	}

      return einfo (SYS_WARN, "Could not locate '%s'", filename);
    }

  if (S_ISDIR (statbuf.st_mode))
    {
      DIR * dir = opendir (filename);

      if (dir == NULL)
	return einfo (SYS_WARN, "unable to read directory: %s", filename);

      struct dirent * entry;
      bool result = true;

      einfo (VERBOSE2, "Scanning directory: '%s'", filename);
      while ((entry = readdir (dir)) != NULL)
	{
	  if (streq (entry->d_name, ".") || streq (entry->d_name, ".."))
	    continue;

	  const char * file = concat (filename, "/", entry->d_name, NULL);
	  result &= process_file (file);
	  free ((char *) file);
	}

      closedir (dir);
      return result;
    }

  if (! S_ISREG (statbuf.st_mode))
    {
      if (ignore_unknown == do_ignore)
	return true;

      return einfo (WARN, "'%s' is not an ordinary file", filename);
    }

  if (statbuf.st_size < 0)
    return einfo (WARN, "'%s' has negative size, probably it is too large", filename);

#ifndef LIBANNOCHECK
  /* If the file is an RPM hand it off for separate processing.  */

  /* FIXME: the rpmReadPackageFile() function can generate a seg-fault
     when processing some rpms (eg: wireshark-cli-2.6.0-3.fc27.aarch64.rpm)
     so just check for a .rpm suffix first.  */
  if ((len = strlen (filename)) > 4 && streq (filename + len - 4, ".rpm"))
    return process_rpm_file (filename);
    
  FD_t rpm_fd;
  if ((rpm_fd = Fopen (filename, "r")) != NULL)
    {
      rpmts  ts = 0;
      Header hdr;
      bool   res = false;

      if (rpmReadPackageFile (ts, rpm_fd, filename, & hdr) == RPMRC_OK)
	res = process_rpm_file (filename);

      Fclose (rpm_fd);
      if (res)
	return true;
    }
#endif /* not LIBANNOCHECK */

  /* Otherwise open it and try to process it as an ELF file.  */
  int fd = open (filename, O_RDONLY);
  if (fd == -1)
    return einfo (SYS_WARN, "Could not open %s", filename);

  Elf * elf = elf_begin (fd, ELF_C_READ, NULL);
  if (elf == NULL)
    {
      close (fd);
      return einfo (WARN, "Unable to parse %s - maybe it is not an RPM or ELF file ?", filename);
    }

  bool ret = process_elf (filename, fd, elf);

  if (elf_end (elf))
    {
      close (fd);
      return einfo (WARN, "Failed to close ELF file: %s", filename);
    }

  if (close (fd))
    return einfo (SYS_WARN, "Unable to close: %s", filename);

  return ret;
}

/* Runs the given CHECKER over the sections and segments in FD.
   The filename associated with FD is assumed to be FILENAME.  */

bool
annocheck_process_extra_file (checker *     checker,
			      const char *  extra_filename,
			      const char *  original_filename,
			      int           fd)
{
  Elf * elf = elf_begin (fd, ELF_C_READ, NULL);

  if (elf == NULL)
    return einfo (WARN, "Unable to parse extra file '%s'", extra_filename);

  bool ret = true;
  if (elf_kind (elf) != ELF_K_ELF)
    return einfo (WARN, "%s: is not an ELF executable file", extra_filename);

  annocheck_data data;

  memset (& data, 0, sizeof data);
  data.full_filename = extra_filename;
  data.filename = original_filename;
  data.fd = fd;
  data.dwarf_fd = -1;
  data.elf = elf;
  data.is_32bit = gelf_getclass (elf) == ELFCLASS32;

  /* Run the start_file callback, if defined.  */
  if (checker->start_file)
    {
      push_component (checker);
      checker->start_file (& data);
      pop_component ();
    }

  size_t shstrndx;

  if (elf_getshdrstrndx (elf, & shstrndx) < 0)
    return einfo (WARN, "%s: Unable to locate string section", extra_filename);
	      
  Elf_Scn * scn = NULL;

  while ((scn = elf_nextscn (elf, scn)) != NULL)
    {
      annocheck_section  sec;

      memset (& sec, 0, sizeof sec);

      sec.scn = scn;

      if (! read_section_header (& data, scn, & sec.shdr))
	continue;

      sec.secname = elf_strptr (elf, shstrndx, sec.shdr.sh_name);	  

      if (sec.secname == NULL)
	/* Fuzzing can produce sections like this.  */
	continue;
      
      /* Note - do not skip empty sections, they may still be interesting to some tools.
	 If a tool is not interested in an empty section, it can always determine this
	 in its interesting_sec() function.  */
      einfo (VERBOSE2, "%s: Examining section %s", extra_filename, sec.secname);

      if (checker->interesting_sec == NULL)
	continue;

      push_component (checker);
      if (checker->interesting_sec (& data, & sec))
	{
	  /* Delay loading the section contents until a checker expresses interest.  */
	  if (sec.data == NULL)
	    {
	      sec.data = elf_getdata (scn, NULL);
	      if (sec.data == NULL)
		ret = einfo (ERROR, "%s: Failed to read in section %s", extra_filename, sec.secname);
	    }

	  if (sec.data != NULL)
	    {
	      einfo (VERBOSE2, "is interested in section %s", sec.secname);

	      assert (checker->check_sec != NULL);
	      ret &= checker->check_sec (& data, & sec);
	    }
	}
      else
	einfo (VERBOSE2, "is not interested in %s", sec.secname);

      pop_component ();
    }

  size_t phnum, cnt;

  elf_getphdrnum (elf, & phnum);

  for (cnt = 0; cnt < phnum; ++cnt)
    {
      GElf_Phdr   mem;
      annocheck_segment seg;

      memset (& seg, 0, sizeof seg);

      seg.phdr = gelf_getphdr (elf, cnt, & mem);

      if (seg.phdr == NULL)
	/* Fuzzing can produce segments like this.  */
	continue;

      seg.number = cnt;

      einfo (VERBOSE2, "%s: considering segment %lu", extra_filename, (unsigned long) cnt);

      if (checker->interesting_seg == NULL)
	continue;

      push_component (checker);

      if (checker->interesting_seg (& data, & seg))
	{
	  /* Delay loading the contents of the segment until they are actually needed.  */
	  if (seg.data == NULL)
	    seg.data = elf_getdata_rawchunk (elf, seg.phdr->p_offset,
					     seg.phdr->p_filesz, ELF_T_BYTE);

	  assert (checker->check_seg != NULL);
	  ret &= checker->check_seg (& data, & seg);
	}
      else
	einfo (VERBOSE2, "is not interested in segment %lu", (unsigned long) cnt);

      pop_component ();
    }

  /* Run the end_file callback, if defined.  */
  if (checker->end_file)
    {
      push_component (checker);
      checker->end_file (& data);
      pop_component ();
    }

  if (elf_end (elf))
    return einfo (WARN, "Failed to close extra file: %s", extra_filename);

  return ret;
}

bool
process_files (void)
{
  bool result = true;
  ulong i;
  
  for (i = 0; i < num_files; i++)
    result &= process_file (files [i]);

  return result;
}

/* -------------------------------------------------------------------- */

bool
annocheck_add_checker (struct checker * new_checker, uint major)
{
  if (major < (ANNOBIN_VERSION / 100))
    return false;

  checker_internal * internal = XCNEW (checker_internal);

  new_checker->internal = internal;
  if (new_checker->interesting_sec)
    {
      internal->next_sec = first_sec_checker;
      first_sec_checker = new_checker;
    }

  if (new_checker->interesting_seg)
    {
      internal->next_seg = first_seg_checker;
      first_seg_checker = new_checker;
    }

  internal->next = first_checker;
  first_checker = new_checker;

  return true;
}

bool
set_debug_file (const char * file)
{
  if (debug_file != NULL)
    einfo (WARN, "overriding previous --debug-file option (%s) with %s",
	   debug_file, file);
  debug_file = file;

  return true;
}

/* -------------------------------------------------------------------- */

#ifndef LIBANNOCHECK

static const char *
create_tmpdir (void)
{
  static char temp[32];

  if (tmpdir != NULL)
    return tmpdir;

  /* This assert can be triggered if a tool defines an END_SCAN function
     but no START_SCAN function.  */
  assert (level == 0);

  strcpy (temp, "annocheck.data.XXXXXX");
  tmpdir = mkdtemp (temp);
  if (tmpdir == NULL)
    {
      einfo (ERROR, "Unable to make temporary data directory");
      return NULL;
    }

  tmpdir = concat (getcwd (NULL, 0), "/", tmpdir, NULL);
  einfo (VERBOSE2, "Created temporary directory for data transfer: %s", tmpdir);

  return tmpdir;
}

static void
print_version (void)
{
  einfo (INFO, "Version %d.%02d", ANNOBIN_VERSION / 100, ANNOBIN_VERSION % 100);

  checker * tool;
  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    if (tool->version)
      {
	push_component (tool);
	einfo (PARTIAL, " ");
	tool->version ();
	pop_component ();
      }
}

static void
usage (void)
{
  einfo (INFO, "Runs various scans on the given files");
  einfo (INFO, "Useage: %s [options] <file(s)>", CURRENT_COMPONENT_NAME);
  einfo (INFO, " Options are:");
  einfo (INFO, "   --debug-rpm=<RPM>  [Find separate dwarf debug information in <RPM>]");
  einfo (INFO, "   --debug-file=<FILE>[Find separate dwarf debug information in <FILE>]");
  einfo (INFO, "   --debug-dir=<DIR>  [Look in <DIR> for separate dwarf debug information files]");
  einfo (INFO, "   --help             [Display this message & exit]");
  einfo (INFO, "   --ignore-unknown   [Do not complain about unknown file types]");
  einfo (INFO, "   --report-unknown   [Do complain about unknown file types]");
  einfo (INFO, "   --quiet            [Do not print anything, just return an exit status]");
  einfo (INFO, "   --verbose          [Produce informational messages whilst working.  Repeat for more information]");
  einfo (INFO, "   --version          [Report the verion of the tool & exit]");
#if HAVE_LIBDEBUGINFOD
  einfo (INFO, "   --use-debuginfod   [Use debuginfod, even if it is available (default)]");
  einfo (INFO, "   --no-use-debuginfod [Do not use debuginfod, even if it is available]");
#endif

  einfo (INFO, "The following options are internal to the scanner and not expected to be supplied by the user:");
  einfo (INFO, "   --prefix=<TEXT>    [Include <TEXT> in the output description]");
  einfo (INFO, "   --tmpdir=<NAME>    [Absolute pathname of a temporary directory used to pass data between iterations]");
  einfo (INFO, "   --level=<N>        [Recursion level of the scanner]");

  einfo (INFO, "Tools have their own options:");
  einfo (INFO, "   --enable-<tool>    [Turn on <tool>][By default the hardened tool is enabled]");
  einfo (INFO, "   --disable-<tool>   [Turn off <tool>]");
  einfo (INFO, "   --<tool>-help      [Display help message for <tool> & exit]");
  einfo (INFO, "   --help-<tool>      [Display help message for <tool> & exit]");
  einfo (INFO, "   --<tool>-<option>  [Pass <option> to <tool>]");
  einfo (INFO, "Tool names are case insensitive, so --hardened-help is the same as --Hardened-help");
  einfo (INFO, "If an option is unique to a tool then it can be passed without the --tool prefix");
  einfo (INFO, "For example the hardened tool's test skipping options can be passed as either");
  einfo (INFO, "--hardened-skip-<test> or just --skip-<test>");
  
  einfo (INFO, "The following scanning tools are available:");

  checker * tool;
  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    einfo (INFO, "  %s\n", tool->name);
}

static void
save_arg (const char * arg)
{
  if (saved_args)
    {
      char * new_saved_args = concat (saved_args, " ", arg, NULL);
      free (saved_args);
      saved_args = new_saved_args;
    }
  else
    saved_args = concat (arg, NULL);
}

/* Handle command line options.  Returns to caller if there is
   something to do.  */

static bool
process_command_line (uint argc, const char * argv[])
{
  uint a = 1;

  progname = component_names[0];

  if (argc > 0 && argv == NULL)
    return false;

  while (a < argc)
    {
      const char *  arg = argv[a];
      bool          used = false;
      checker *     tool;
      const char *  orig_arg = arg;

      ++ a;

      for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
	{
	  if (arg[0] == '-' && arg[1] == '-' && strncasecmp (arg + 2, tool->name, strlen (tool->name)) == 0)
	    {
	      arg += 2 + strlen (tool->name);
	      if (arg[0] == '-')
		++arg;

	      if (streq (arg, "help"))
		{
		  if (tool->usage)
		    {
		      push_component (tool);
		      tool->usage ();
		      pop_component ();
		    }
		  else
		    einfo (INFO, "Tool %s does not have any specific options", tool->name);

		  exit (EXIT_SUCCESS);
		}	      

	      if (tool->process_arg != NULL)
		{
		  push_component (tool);
		  if (tool->process_arg (arg, argv, argc, & a))
		    used = true;
		  pop_component ();
		}

	      if (! used)
		goto unknown_arg;
	    }
	  else if (tool->process_arg != NULL)
	    {
	      push_component (tool);
	      if (tool->process_arg (arg, argv, argc, & a))
		used = true;
	      pop_component ();
	    }
	}

      if (used)
	{
	  save_arg (arg);
	  continue;
	}

      if (arg[0] == '-')
        {
	  const char *  parameter;

	  arg += (arg[1] == '-' ? 2 : 1);
	  switch (*arg)
	    {
	    case 'h': /* --help */
	      /* As an assit to users treat --help-<tool> as --<tool>-help.  */
	      if (const_strneq (arg, "help-"))
		{
		  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
		    {
		      if (tool->usage
			  && strncasecmp (arg + strlen ("help-"), tool->name, strlen (tool->name)) == 0)
			{
			  push_component (tool);
			  tool->usage ();
			  pop_component ();
			  exit (EXIT_SUCCESS);
			}
		    }
		}
	      usage ();
	      exit (EXIT_SUCCESS);

	    case 'i': /* --ignore-unknown  */
	      ignore_unknown = do_ignore;
	      break;

	    case 'r': /* --report-unknown  */
	      ignore_unknown = do_not_ignore;
	      break;

	    case 'q': /* --quiet */
	      save_arg (orig_arg);
	      verbosity = -1UL;
	      break;

	    case 'd': /* --debug-rpm, --debug-file or --debug-dir.  */
	      parameter = strchr (arg, '=');
	      if (parameter == NULL)
		parameter = argv[a++];
	      else
		parameter ++;

	      if (const_strneq (arg, "dwarf-dir") /* Old name for --debug-dir.  */
		  || const_strneq (arg, "debug-dir")
		  || const_strneq (arg, "debugdir"))
		{
		  if (debug_path != NULL)
		    einfo (WARN, "overriding previous --debug-dir option (%s) with %s",
			   debug_path, parameter);
		  debug_path = parameter;
		}
	      else if (const_strneq (arg, "debug-rpm") || const_strneq (arg, "debugrpm"))
		{
		  if (debug_rpm != NULL)
		    einfo (WARN, "overriding previous --debug-rpm option (%s) with %s",
			   debug_rpm, parameter);
		  debug_rpm = parameter;
		}
	      else if (const_strneq (arg, "debug-file") || const_strneq (arg, "debugfile"))
		{
		  set_debug_file (parameter);
		}
	      else
		goto unknown_arg;

	      if (parameter == NULL)
		goto arg_missing_argument;

	      if (parameter[0] != '/')
		{
		  const char * tmp;
		  /* Convert a relative path to an absolute one so that if/when
		     we recurse into a directory, the path will remain valid.  */
		  if (parameter == argv[a-1])
		    tmp = concat (orig_arg, " ", getcwd (NULL, 0), "/", parameter, NULL);
		  else if (debug_rpm == parameter)
		    tmp = concat ("--debug-rpm=", getcwd (NULL, 0), "/", parameter, NULL);
		  else if (debug_path == parameter)
		    tmp = concat ("--debug-dir=", getcwd (NULL, 0), "/", parameter, NULL);
		  else /* debug_file == parameter  */
		    tmp = concat ("--debug-file=", getcwd (NULL, 0), "/", parameter, NULL);
		  save_arg (tmp);
		  free ((void *) tmp);
		}
	      else
		{
		  save_arg (orig_arg);
		  if (parameter == argv[a-1])
		    save_arg (parameter);
		}

	      if (debug_path != NULL && debug_rpm != NULL)
		{
		  static bool warned = false;
		  if (! warned)
		    einfo (WARN, "Behaviour is undefined when both --debug-rpm and --debug-dir are specified");
		  warned = true;
		}
	      break;

	    case 'p': /* --prefix  */
	      save_arg (orig_arg);
	      parameter = strchr (arg, '=');
	      if (parameter == NULL)
		parameter = argv[a++];
	      else
		parameter ++;

	      if (parameter == NULL)
		goto arg_missing_argument;

	      /* Prefix arguments accumulate.  */
	      prefix = concat (prefix, parameter, NULL);
	      break;

	    case 'l': /* --level */
	      parameter = strchr (arg, '=');
	      if (parameter == NULL)
		parameter = argv[a++];
	      else
		parameter ++;	      

	      if (parameter == NULL)
		goto arg_missing_argument;

	      level = strtoul (parameter, NULL, 0);
	      if (level < 1)
		{
		  einfo (WARN, "improper --level option: %s", parameter);
		  level = 1;
		}
	      break;

	    case 't': /* --tmpdir */
	      if (const_strneq (arg, "tmpdir"))
		{
		  parameter = strchr (arg, '=');
		  if (parameter == NULL)
		    parameter = argv[a++];
		  else
		    parameter ++;	      

		  if (parameter == NULL)
		    goto arg_missing_argument;

		  tmpdir = parameter;
		  assert (tmpdir[0] == '/');
		}
	      else
		goto unknown_arg;
	      break;
	      
	    case 'v': /* --verbose or --version.  */
	      if (const_strneq (arg, "version"))
		{
		  print_version ();
		  exit (EXIT_SUCCESS);
		}
	      else if (const_strneq (arg, "verbose")
		       /* Allow -v as an alias for --verbose.  */
		       || arg[1] == 0)
		{
		  save_arg (orig_arg);
		  verbosity ++;
		}
	      else
		goto unknown_arg;
	      break;

	    case 'u':
	      if (streq (arg, "use-debuginfod"))
		{
#if HAVE_LIBDEBUGINFOD
		  use_debuginfod = true;
#else
		  einfo (WARN, "debuginfod is not supported by this build of annocheck");
#endif
		}
	      else
		goto unknown_arg;
	      break;

	    case 'n':
	      if (streq (arg, "no-use-debuginfod"))
		{
#if HAVE_LIBDEBUGINFOD
		  use_debuginfod = false;
#else
		  /* Do not warn, just silently accept.  */
#endif
		}
	      else
		goto unknown_arg;
	      break;

	    default:
	    unknown_arg:
	      einfo (WARN, "Unrecognised command line option: %s", orig_arg);
	      usage ();
	      return false;
	    arg_missing_argument:
	      einfo (ERROR, "Command line option '%s' needs an argument", orig_arg);
	      return false;
	    }
	}
      else
	add_file (arg);
    }

  if (num_files == 0)
    {
      einfo (WARN, "No input files specified");
      usage ();
      return false;
    }

  return true;
}

int
main (int argc, const char ** argv)
{
  checker *     tool;
  bool          self_made_tmpdir = false;

  if (argv != NULL && argv[0] != NULL)
    {
      full_progname = argv[0];
      component_names[0] = lbasename (argv[0]);
    }
  else
    component_names[0] = full_progname = "annocheck";

  if (elf_version (EV_CURRENT) == EV_NONE)
    {
      einfo (FAIL, "Could not initialise libelf");
      return EXIT_FAILURE;
    }

  if (rpmReadConfigFiles (NULL, NULL) != 0)
    {
      einfo (FAIL, "Could not initialise librpm");
      return EXIT_FAILURE;
    }

  if (! process_command_line (argc, argv))
    return EXIT_FAILURE;

  if (level == 0)
    einfo (INFO, "Version %d.%02d", ANNOBIN_VERSION / 100, ANNOBIN_VERSION % 100);
  
  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    if (tool->start_scan != NULL)
      {
	checker_internal * internal = (checker_internal *)(tool->internal);

	if (internal->datafile == NULL)
	  {
	    if (tmpdir == NULL)
	      {
		assert (level == 0);
		tmpdir = create_tmpdir ();
		if (tmpdir == NULL)
		  return EXIT_FAILURE;
		self_made_tmpdir = true;
	      }

	    if (tmpdir[strlen (tmpdir) - 1] == '/')
	      internal->datafile = concat (tmpdir, tool->name, NULL);
	    else
	      internal->datafile = concat (tmpdir, "/", tool->name, NULL);
	  }

	push_component (tool);
	tool->start_scan (level, internal->datafile);
	pop_component ();
      }
  
  bool res = process_files ();

  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    if (tool->end_scan != NULL)
      {
	checker_internal * internal = (checker_internal *)(tool->internal);

	if (internal->datafile == NULL)
	  {
	    einfo (ERROR, "data file should have already been created");
	    continue;
	  }
	push_component (tool);
	tool->end_scan (level, internal->datafile);
	pop_component ();

	free ((char *) internal->datafile);
      }
  
 if (debug_rpm_dir)
   {
     char * command = concat ("rm -fr ", debug_rpm_dir, NULL);
     if (system (command))
       einfo (WARN, "Failed to delete temporary directory: %s", debug_rpm_dir);
     free (command);
   }

  if (self_made_tmpdir)
    {
      assert (level == 0);
      assert (tmpdir != 0);
      rmdir (tmpdir);
    }

  return res ? EXIT_SUCCESS : EXIT_FAILURE;
}

#endif /* not LIBANNOCHECK */
