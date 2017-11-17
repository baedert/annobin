#include <stdio.h>

extern int big_stack (int);

int baz (void) __attribute__((optimize("-O0"),__noinline__));
int bar (void) __attribute__((optimize("-fstack-protector-strong"),__noinline__));

int
bar (void)
{
  return 2;
}

int
main (void)
{
  return printf ("hello world %d %d %d\n", bar (), baz (), big_stack (3));
}

int
baz (void)
{
  return 3;
}

