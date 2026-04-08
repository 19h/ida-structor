#if defined(__aarch64__)
	.text
	.align 2
	.globl _regarg_callee
_regarg_callee:
	add	w0, w19, #7
	ret

	.globl _regarg_caller
_regarg_caller:
	stp	x29, x30, [sp, #-32]!
	mov	x29, sp
	str	x19, [sp, #16]
	mov	w19, w0
	bl	_regarg_callee
	ldr	x19, [sp, #16]
	ldp	x29, x30, [sp], #32
	ret
#endif
