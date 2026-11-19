/* Shared library built with lazy binding and a relative RUNPATH (both bad). */
#include <string.h>

int demo_len(const char *s)
{
	return (int)strlen(s);
}
