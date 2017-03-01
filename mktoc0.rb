#!/usr/bin/env ruby
#
# Copyright (c) 2017 Jens Kuske <jenskuske@gmail.com>
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

if ARGV.length < 3
	puts "Usage: #{$PROGRAM_NAME} key_file input_file output_file"
	puts
	puts "Example:\n"
	puts "   openssl genrsa -out privkey.pem 2048"
	puts "   #{$PROGRAM_NAME} privkey.pem sunxi-spl.bin output.img"
	puts "   dd if=output.img of=/dev/sdX bs=1024 seek=8"
	exit false
end

File.binwrite(ARGV[2], TOC0::mktoc0(File.read(ARGV[0]),
                                    File.binread(ARGV[1]),
                                    0x0))
