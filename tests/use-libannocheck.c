/* use-libannocheck.c - Test the libannocheck library.
   Copyright (c) 2021 Red Hat.
   Created by Nick Clifton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "libannocheck.h"

int
main (void)
{
  void * handle;

  handle = libannocheck_init (libannocheck_version, "fred", "jim");
  if (handle == NULL)
    {
      printf ("FAILED to open library\n");
      return EXIT_FAILURE;
    }

  printf ("open library: PASS\n");

  printf ("Library version: %u (header version %u)\n",
	  libannocheck_get_version (handle),
	  libannocheck_version);

  libannocheck_error   res;
  libannocheck_test *  tests;
  unsigned int         num_tests;

  if ((res = libannocheck_get_known_tests (handle, & tests, & num_tests)) != libannocheck_error_none)
    {
      printf ("FAILED to get_tests\n");
      libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  printf ("got test list containing %u entries\n", num_tests);

  if ((res = libannocheck_disable_all_tests (handle)) != libannocheck_error_none)
    {
      printf ("FAILED to disable all tests\n");
      libannocheck_finish (handle);
      return EXIT_FAILURE;
    }
  
  if ((res = libannocheck_enable_all_tests (handle)) != libannocheck_error_none)
    {
      printf ("FAILED to enable all tests\n");
      libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  if ((res = libannocheck_enable_profile (handle, "el8")) != libannocheck_error_none)
    {
      printf ("FAILED to enable el8 profilen");
      libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  if ((res = libannocheck_enable_test (handle, "bind-now")) != libannocheck_error_none)
    {
      printf ("FAILED to enable bind-now");
      libannocheck_finish (handle);
      return EXIT_FAILURE;
    }
  
  if ((res = libannocheck_disable_test (handle, "bind-now")) != libannocheck_error_none)
    {
      printf ("FAILED to disable bind-now");
      libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  printf ("Enabled and disabled tests\n");

  unsigned int num_fails, num_maybs;

  if ((res = libannocheck_run_tests (handle, & num_fails, & num_maybs)) != libannocheck_error_none)
    {
      printf ("FAILED to run tests");
      libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  printf ("Ran tests, %u fails, %u maybs\n", num_fails, num_maybs);

  if (libannocheck_finish (handle) != libannocheck_error_none)
    {
      printf ("FAILED to close library\n");
      return EXIT_FAILURE;
    }

  printf ("close library: PASS\n");
  
  return EXIT_SUCCESS;
}
