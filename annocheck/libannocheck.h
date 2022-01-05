/* libannocheck.h - Header file for the libannocheck library.
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

#ifdef __cplusplus
extern "C" {
#endif

/* NB/ Keep this value in sync with ANNOBIN_VERSION defined in
   annobin-global.h.  */
const unsigned int libannocheck_version = 1041;

typedef enum libannocheck_error
{
  libannocheck_error_none = 0,
  libannocheck_error_bad_arguments,
  libannocheck_error_bad_handle,
  libannocheck_error_bad_version,
  libannocheck_error_debug_file_not_found,
  libannocheck_error_file_corrupt,
  libannocheck_error_file_not_ELF,
  libannocheck_error_file_not_found,
  libannocheck_error_out_of_memory,
  libannocheck_error_not_supported,
  libannocheck_error_profile_not_known,
  libannocheck_error_test_not_found,
  
  libannocheck_error_MAX
} libannocheck_error;

typedef enum libannocheck_test_state
{
  libannocheck_test_state_not_run = 0,
  libannocheck_test_state_passed,
  libannocheck_test_state_failed,
  libannocheck_test_state_maybe,
  libannocheck_test_state_skipped,

  libannocheck_test_state_MAX  
} libannocheck_test_state;
    
typedef struct libannocheck_test
{
  const char *             name;
  const char *             description;
  const char *             doc_url;
  const char *             result_reason;
  const char *             result_source;
  libannocheck_test_state  state;
  bool                     enabled;
} libannocheck_test;

/* Initialise the libannocheck library.
   Returns a token used to identify the instantiation in future calls.
   VERSION is the expected version of the libannocheck library.  This should normally be 'libannocheck_version'.
    If the actual version of the library cannot support VERSION then libannocheck_error_bad_version is returned.
   FILEPATH is a path the binary to be tested.  It can be absolute or relative.
   DEBUGPATH is a path the debug info file associated with FILEPATH.  It can be NULL. 
   Returns an enum libannocheck_error cast to a struct libannocheck_internals * if something goes wrong.  */
extern struct libannocheck_internals * libannocheck_init (unsigned int VERSION, const char * FILEPATH, const char * DEBUGPATH);

/* Terminates a library session.  Closes any open files.
   After this any library call using HANDLE should fail.
   Returns libannocheck_error_none upon successful closure, otherwise returns an error code.  */
extern libannocheck_error  libannocheck_finish (struct libannocheck_internals * HANDLE);

/* Returns a (read only) string describing an libannocheck error.
   Returns NULL if the error code is not recognised.
   Handle can be NULL if one is not available.
   A more detailed error message may be returned if HANDLE is provided.  */
extern const char *        libannocheck_get_error_message (struct libannocheck_internals * HANDLE, enum libannocheck_error ERRNUM);

/* Returns the actual version number of the libannocheck_library.
   This should be >= libannocheck_version as defined in this file.  */
extern unsigned int        libannocheck_get_version (void);

/* Returns a (read/write) array of tests known to libannocheck in TESTS_RETURN.
   Returns the number of elements in the array in NUM_TESTS_RETURN.
   Returns libannocheck_error_none if the retrieval succeeded, or an error result otherwise.
   The returned array should not be freed.
   The array is used by libannocheck internally, so if fields are changed
    this will affect the library's behaviour.  In particular tests can be
    enabled and disabled without needing to call libannocheck_enable_test()
    or libannocheck_disable_test().
   The test_result_reason and test_result_source fields will initially be NULL.
   They may have their values changed as a result of a call to libannocheck_run_tests().  */
extern libannocheck_error  libannocheck_get_known_tests (struct libannocheck_internals * HANDLE, libannocheck_test ** TESTS_RETURN, unsigned int * NUM_TESTS_RETURN);

/* The following five function calls affect the data held in the array returned
   by libannocheck_get_known_tests().  */
extern libannocheck_error  libannocheck_enable_all_tests (struct libannocheck_internals * HANDLE);
extern libannocheck_error  libannocheck_disable_all_tests (struct libannocheck_internals * HANDLE);
/* These functions allow the enabling and disabling of tests by name.
   This allows tests to be controlled without having to retrieve the entire test array.  */
extern libannocheck_error  libannocheck_enable_test (struct libannocheck_internals * HANDLE, const char * TEST_NAME);
extern libannocheck_error  libannocheck_disable_test (struct libannocheck_internals * HANDLE, const char * TEST_NAME);
/* Enables and disables certain tests known to be relevant to a specific profile.
   Returns libannocheck_error_profile_not_known if the profile is not recognised.  */
extern libannocheck_error  libannocheck_enable_profile (struct libannocheck_internals * HANDLE, const char * PROFILE_NAME);

/* Retrieves a (read only) array of profile strings known to libannocheck.
   The array is returned in PROFILES_RETURN.
   The number of entries in the array is returned in NUM_PROFILES.
   Returns libannocheck_error_none upons success, or an error code otherwise.  */
extern libannocheck_error  libannocheck_get_known_profiles (struct libannocheck_internals * HANDLE, const char *** PROFILES_RETURN, unsigned int * NUM_PROFILES_RETURN);

/* Runs all enabled tests.
   Returns the number of failed tests in NUM_FAIL_RETURN (if this parameter is not NULL).
   Returns the number of "maybe" results in NUM_MAYB_RETURN (if this parameter is not NULL).
   Retuns libannocheck_error_none if everything went OK.
   Updates the STATE, TEST_RESULT_REASON and TEST_RESULT_SOURCES fields in the entries in
   the array returned by libannocheck_get_known_tests() for any enabled test.
   Can be called multiple times.  */
extern libannocheck_error  libannocheck_run_tests (struct libannocheck_internals * HANDLE, unsigned int * NUM_FAIL_RETURN, unsigned int * NUM_MAYB_RETURN);

#ifdef __cplusplus
}
#endif
