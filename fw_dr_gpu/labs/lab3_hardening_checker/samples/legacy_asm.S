/*
 * A hand-written x86-64 routine with NEITHER a .note.GNU-stack section
 * NOR an endbr64 / .note.gnu.property CET marking.
 *
 * Linking this one object into an otherwise hardened program:
 *   - makes the whole program's stack executable (unless -Wl,-z,noexecstack), and
 *   - silently drops the CET IBT/SHSTK property for the whole program,
 * because the linker ANDs these properties across every input object.
 *
 * The fix: add
 *     .section .note.GNU-stack,"",@progbits
 * and assemble with -Wa,-mx86-used-note / emit the GNU property note (gcc does it
 * for .S files when compiled with -fcf-protection and the file includes <cet.h>),
 * plus `endbr64` at every indirect-branch target.
 */
	.text
	.globl	legacy_add
	.type	legacy_add, @function
legacy_add:
	leal	(%rdi,%rsi), %eax
	ret
	.size	legacy_add, .-legacy_add
