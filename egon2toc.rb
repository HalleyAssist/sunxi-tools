#!/usr/bin/env ruby
#
# Copyright (c) 2017 Siarhei Siamashka <siarhei.siamashka@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

require './libtoc0.rb'

# Just some private key, it does not matter which one
privkey_pem = File.read(ARGV[1])

if ARGV.length < 3
	puts "Usage: #{$PROGRAM_NAME} input_file private_key_file output_file [spl_addr]"
	exit false
end

# Use SRAM A2 by default (and autodetect SRAM A1 address)
load_base = 0x44000

if ARGV[3]
	load_base = ARGV[3].to_i(16)
	if (load_base != 0x0) && (load_base != 0x10000)
		abort "'spl_addr' argument must be either 0x0 or 0x10000."
	end
end

code = File.binread(ARGV[0])
egon_hdr = code.unpack("L<A8L<L<")

if ((egon_hdr[0] >> 24) != 0xEA) || (egon_hdr[1] != "eGON.BT0")
	abort "'#{ARGV[0]}' does not have a eGON header."
end

# Extract the SPL header size from the branch instruction offset
egon_hdr_size = (egon_hdr[0] & 0xFFFFFF) * 4 + 8
if (egon_hdr_size % 32 != 0) || (egon_hdr_size > 32 * 1024)
	abort "'#{ARGV[0]}' has invalid eGON header size."
end

# Extract the SPL size from the eGON header
egon_spl_size = egon_hdr[3]
if (egon_spl_size % 0x2000 != 0) || (egon_spl_size > code.size)
	abort "'#{ARGV[0]}' has invalid SPL size in the eGON header."
end

if (egon_spl_size > 24 * 1024) && load_base == 0x44000
	abort "The SPL is larger than 24K, so 'spl_addr' argument is required."
end

chunk1_size = 0x34

toc0_fixup_stub = "
		htole32(0xee114f10), /*    0:  mrc   15, 0, r4, cr1, cr0, {0} */
		htole32(0xe3140a02), /*    4:  tst   r4, #8192               */
		htole32(0x13a04000), /*    8:  movne r4, #0                  */
		htole32(0x03a04801), /*    c:  moveq r4, #65536              */
		htole32(0xe5d4c020), /*   10:  ldrb  ip, [r4, #32]           */
		htole32(0xe59f0058), /*   14:  ldr   r0, [pc, #88]           */
		htole32(0xe59f1058), /*   18:  ldr   r1, [pc, #88]           */
		htole32(0xe59f2058), /*   1c:  ldr   r2, [pc, #88]           */
		htole32(0xe0800004), /*   20:  add   r0, r0, r4              */
		htole32(0xe1500001), /*   24:  cmp   r0, r1                  */
		htole32(0x0a000003), /*   28:  beq   3c <toc0_fixup_stub+0x3c> */
		htole32(0xe2522004), /*   2c:  subs  r2, r2, #4              */
		htole32(0xe7913002), /*   30:  ldr   r3, [r1, r2]            */
		htole32(0xe7803002), /*   34:  str   r3, [r0, r2]            */
		htole32(0x1afffffb), /*   38:  bne   2c <toc0_fixup_stub+0x2c> */
		htole32(0xe59f003c), /*   3c:  ldr   r0, [pc, #60]           */
		htole32(0xe59f103c), /*   40:  ldr   r1, [pc, #60]           */
		htole32(0xe59f203c), /*   44:  ldr   r2, [pc, #60]           */
		htole32(0xe0800004), /*   48:  add   r0, r0, r4              */
		htole32(0xe1500001), /*   4c:  cmp   r0, r1                  */
		htole32(0x0a000003), /*   50:  beq   64 <toc0_fixup_stub+0x64> */
		htole32(0xe2522004), /*   54:  subs  r2, r2, #4              */
		htole32(0xe7913002), /*   58:  ldr   r3, [r1, r2]            */
		htole32(0xe7803002), /*   5c:  str   r3, [r0, r2]            */
		htole32(0x1afffffb), /*   60:  bne   54 <toc0_fixup_stub+0x54> */
		htole32(0xe5c4c028), /*   64:  strb  ip, [r4, #40]           */
		htole32(0xf57ff04f), /*   68:  dsb   sy                      */
		htole32(0xf57ff06f), /*   6c:  isb   sy                      */
		htole32(0xe12fff14), /*   70:  bx    r4                      */
".scan(/htole32\((.+?)\)/).map { |x| x[0].to_i(16) }

toc0_fixup_stub += [chunk1_size, load_base + chunk1_size, egon_spl_size - chunk1_size]
toc0_fixup_stub += [0x0, load_base + chunk1_size + egon_spl_size - chunk1_size, chunk1_size]

transformed_code = [0xEA000000 + (egon_spl_size + 4 - 8) / 4].pack("L<") +
                   code.byteslice(chunk1_size, egon_spl_size - chunk1_size) +
                   code.byteslice(0, chunk1_size) +
                   toc0_fixup_stub.pack("L<*")

File.binwrite(ARGV[1], TOC0::mktoc0(privkey_pem, transformed_code, load_base + chunk1_size - 4))
