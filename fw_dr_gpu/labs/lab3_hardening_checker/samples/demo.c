/* Tiny program used to show how compiler/linker flags show up in the binary. */
#include <stdio.h>
#include <string.h>

#ifdef USE_ASM
int legacy_add(int a, int b);   /* implemented in legacy_asm.S */
#endif

int main(int argc, char **argv)
{
	char buf[64];                         /* local array -> stack protector */
	const char *who = argc > 1 ? argv[1] : "world";

	if (strlen(who) < 32)
		strcpy(buf, who);             /* -> __strcpy_chk with _FORTIFY_SOURCE */
	else
		snprintf(buf, sizeof(buf), "%.31s", who);   /* -> __snprintf_chk */
	printf("hello, %s\n", buf);           /* -> __printf_chk with _FORTIFY_SOURCE=2+ */
#ifdef USE_ASM
	printf("legacy_add(2, 3) = %d\n", legacy_add(2, 3));
#endif
	return 0;
}
