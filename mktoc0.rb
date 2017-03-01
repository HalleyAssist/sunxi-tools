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

key = OpenSSL::PKey::RSA.new(File.read(ARGV[0]))
code = File.binread(ARGV[1])

cert = Certificate.new(key, OpenSSL::Digest::SHA256.digest(code))

toc0_cert = TOC0Item.new(0x010101, cert.to_der, TOC0Item::CERTIFICATE)
toc0_code = TOC0Item.new(0x010202, code, TOC0Item::CODE, 0x0)

toc0 = TOC0.new( [ toc0_cert, toc0_code ] )

File.binwrite(ARGV[2], toc0.to_s)
