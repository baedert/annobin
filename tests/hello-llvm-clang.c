#include <stdio.h>
#include <string.h>

char buf[128];

int 
main (int argc, char ** argv)
{
  strcpy (buf, argv[0]);
  return printf ("%s", buf);
}
