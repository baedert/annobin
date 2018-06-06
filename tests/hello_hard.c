#include <stdio.h>

extern int big_stack (int);

int bar (void) __attribute__((optimize("-fstack-protector-strong"),__noinline__));

int
ordinary_func (void)
{
  return 77;
}

int
bar (void)
{
  return 2;
}

int
baz (void)
{
  return 3;
}

int
main (void)
{
  return printf ("hello world %d %d %d\n", bar (), baz (), big_stack (3));
}

