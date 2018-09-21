
int unused_func_1 (void) __attribute__((optimize("-O1"),__noinline__));

int
unused_func_1 (void)
{
  return 22;
}

int
extern_func2 (void)
{
  return 23;
}

int
extern_func3 (void)
{
  return 24;
}

int unused_func_2 (void) __attribute__((optimize("-O0"),__noinline__));

int
unused_func_2 (void)
{
  return 25;
}

int linkonce_func_1 (void) __attribute ((section (".gnu.linkonce.t.linkonce_func_1")));
int linkonce_func_1 (void) __attribute__((optimize("-O0"),__noinline__));

int
linkonce_func_1 (void)
{
  return 26;
}

void * foo_ifunc (void) __asm__ ("food");

__asm__(".type foo, %gnu_indirect_function");

static float
foo_impl (float x)
{
  return x + 1;
}

void * foo_ifunc (void) __attribute__((optimize("-O0"),__noinline__));

void *
foo_ifunc (void)
{
  asm volatile (".dc.l 0" );
  return foo_impl;
}

extern int bar (int);
extern int baz (int) __attribute__((cold));

void coldy (int) __attribute__((optimize("-O3"),__noinline__));

void
coldy (int x)
{
  if (x)
    bar (bar (5));
  else
    baz (baz (baz (baz (12))));
}

void
colder (int x)
{
  if (x)
    bar (bar (7));
  else
    baz (baz (baz (baz (13))));
}

void * func_in_its_own_section (void) __attribute__((optimize("-O3"),section(".mysection"),__noinline__));

void *
func_in_its_own_section (void)
{
  asm volatile (".dc.l 0" );
  return 0;
}

int disabled = -1;

static __attribute__((constructor)) void
constructor_func (void) 
{
  disabled = 1;
}

static __attribute__((destructor)) void
destructor_func (void) 
{
  disabled = 0;
}
