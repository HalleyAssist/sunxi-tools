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

if ARGV.length < 2
	puts "Usage: #{$PROGRAM_NAME} input_file output_file"
	puts
	puts "This tool extracts a bootable eGON image from a TOC0 file."
	puts "Note: the input TOC0 file is expected to be created by the"
	puts "'egon2toc.rb' script."
	exit false
end

toc0 = File.binread(ARGV[0])

toc0_name, toc0_magic, toc0_num_items = toc0.unpack("A8L<6")

if (toc0_name != "TOC0.GLH") || (toc0_magic != 0x89119800)
	abort "'#{ARGV[0]}' does not have a TOC0 header."
end

toc0_num_items, toc0_length = toc0.byteslice(0x18, 8).unpack("L<2")

toc0_num_items.times do |idx|
	toc0_item = toc0.byteslice(0x30 + idx * 0x20, 0x20)
	item_id, item_offset, item_length = toc0_item.unpack("L<3")
	next unless item_id == 0x010202

	run_address = toc0_item.byteslice(0x14, 4).unpack("L<")[0]
	code = toc0.byteslice(item_offset, item_length)

	chunk1_size = (run_address % 0x1000) + 4

	if chunk1_size < 0x28 || chunk1_size > 0x480
		abort "TOC0 item: unexpected run address."
	end

	branch_instr = code.unpack("L<")[0]
	if (branch_instr >> 24) != 0xEA
		abort "TOC0 item: no branch instruction found at start."
	end

	branch_offs = (branch_instr & 0xFFFFFF) * 4 + 8
	chunk1 = code.byteslice(branch_offs - chunk1_size, chunk1_size)
	chunk2 = code.byteslice(4, branch_offs - 4 - chunk1_size)
	egon = chunk1 + chunk2

	egon_branch_instr, egon_name = egon.unpack("L<A8")
	if ((egon_branch_instr >> 24) != 0xEA) || (egon_name != "eGON.BT0")
		abort "TOC0 item: no eGON header."
	end

	File.binwrite(ARGV[1], egon)
	exit 0
end

abort "Could not find any eGON image inside."
