
int unused_func (void) __attribute__((optimize("-fstack-protector-explicit"),__noinline__));

int
unused_func (void)
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

int
unused_end (void)
{
  return 25;
}
