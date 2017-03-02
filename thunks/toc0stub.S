toc0_fixup_stub:
	/* r4 = autodetected SRAM A1 address */
	mrc	p15, 0, r4, c1, c0, 0
	tst	r4, #(1 << 13) /* SCTRL.V */
	movne	r4, #0x00000
	moveq	r4, #0x10000

	/* ip = boot media type from the TOC0 header */
	ldrb	ip, [r4, #0x20]

	/* dst, src and size of the first block */
	ldr	r0, 1f
	ldr	r1, 2f
	ldr	r2, 3f
	add	r0, r4
	/* check if the copy operation may be skipped */
	cmp	r0, r1
	beq	9f
0:	subs	r2, r2, #4
	ldr	r3, [r1, r2]
	str	r3, [r0, r2]
	bne	0b
9:
	/* dst, src and size of the second block */
	ldr	r0, 4f
	ldr	r1, 5f
	ldr	r2, 6f
	add	r0, r4
	/* check if the copy operation may be skipped */
	cmp	r0, r1
	beq	9f
0:	subs	r2, r2, #4
	ldr	r3, [r1, r2]
	str	r3, [r0, r2]
	bne	0b
9:
	/* write boot media type to the eGON header */
	strb	ip, [r4, #0x28]
	dsb
	isb
	bx	r4

1:	.word	0	/* dst1 */
2:	.word	0	/* src1 */
3:	.word	0	/* size1 (must be non-zero and divisible by 4) */

4:	.word	0	/* dst2 */
5:	.word	0	/* src2 */
6:	.word	0	/* size2 (must be non-zero and divisible by 4) */
