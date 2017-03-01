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

require 'openssl'

class RawASN1
	def initialize(type, value)
		@type = type
		@value = value
	end

	def to_der
		if @value.length < 128
			[ @type, @value.length ].pack('CC') + @value
		elsif @value.length < 256
			[ @type, 0x81, @value.length ].pack('CCC') + @value
		else
			[ @type, 0x82, @value.length ].pack('CCn') + @value
		end
	end
end

class Certificate < OpenSSL::ASN1::Sequence
	def initialize(key, hash)
		certificate = TBSCertificate(key.public_key, hash)
		signature = Signature(sign(key, certificate.to_der[0...-4]))
		super( [ certificate, signature ] )
	end

	private

	def AlgorithmIdentifier(algorithm)
		algorithm = OpenSSL::ASN1::ObjectId.new(algorithm)
		parameters = OpenSSL::ASN1::Null.new(nil)
		OpenSSL::ASN1::Sequence.new( [ algorithm, parameters ] )
	end

	def SubjectPublicKeyInfo(n, e)
		algorithm = AlgorithmIdentifier('rsaEncryption')
		n = RawASN1.new(OpenSSL::ASN1::INTEGER, [n.to_s(16)].pack('H*'))
		e = RawASN1.new(OpenSSL::ASN1::INTEGER, [e.to_s(16)].pack('H*'))
		subjectPublicKey = OpenSSL::ASN1::Sequence.new( [ n, e ] )
		OpenSSL::ASN1::Sequence.new( [ algorithm, subjectPublicKey ] )
	end

	def Payload(hash)
		hash = RawASN1.new(OpenSSL::ASN1::INTEGER, hash)
		OpenSSL::ASN1::Sequence.new( [ hash ], 3, :EXPLICIT)
	end

	def TBSCertificate(pubkey, hash)
		version = OpenSSL::ASN1::Integer.new(2, 0, :EXPLICIT)
		serial = OpenSSL::ASN1::Integer.new(2)
		signature = AlgorithmIdentifier('sha256WithRSAEncryption')
		issuer = OpenSSL::ASN1::Sequence.new( [] )
		validity = OpenSSL::ASN1::Sequence.new( [] )
		subject = OpenSSL::ASN1::Sequence.new( [] )
		subjectPublicKeyInfo = SubjectPublicKeyInfo(pubkey.params['n'], pubkey.params['e'])
		payload = Payload(hash)

		OpenSSL::ASN1::Sequence.new( [ version, serial, signature, issuer, validity, subject, subjectPublicKeyInfo, payload ] )
	end

	def sign(key, data)
		hash = OpenSSL::Digest::SHA256.digest(data).rjust(256, "\0")
		key.private_encrypt(hash, OpenSSL::PKey::RSA::NO_PADDING)
	end

	def Signature(signature)
		signatureAlgorithm = AlgorithmIdentifier('rsassaPss')
		signatureValue = RawASN1.new(OpenSSL::ASN1::BIT_STRING, signature)
		signature = signatureAlgorithm.to_der + signatureValue.to_der
		RawASN1.new(OpenSSL::ASN1::BIT_STRING, signature)
	end
end

def align(value, alignment)
	(value + alignment - 1) & ~(alignment - 1)
end

class TOC0Item
	CERTIFICATE = 1
	CODE = 2

	def initialize(id, data, type, run_addr = 0)
		@id = id
		@data = data
		@type = type
		@run_addr = run_addr
	end

	def get_header(offset)
		[ @id, offset, @data.length, 0, @type, @run_addr, 0, 'IIE;' ].pack('V7a4')
	end

	def get_data
		@data.ljust(align(@data.length, 32), "\0")
	end
end

class TOC0
	def initialize(items)
		@items = items
	end

	def to_s
		header_len = align(48 + @items.length * 32, 32)
		headers = ''
		data = ''

		@items.each do |item|
			headers << item.get_header(header_len + data.length)
			data << item.get_data()
		end

		total_length = align(header_len + data.length, 16 * 1024)

		main_header = pack_header(@items.length, total_length)

		checksum = (main_header + headers + data).unpack('V*').reduce(:+) % 2 ** 32
		main_header = pack_header(@items.length, total_length, checksum)

		headers = (main_header + headers).ljust(header_len, "\0")
		(headers + data).ljust(total_length, "\0")
	end

	private

	def pack_header(num_items, length, checksum = 0x5F0A6C39)
		[ 'TOC0.GLH', 0x89119800, checksum, 0, 0, num_items, length, 0, 0, 0, 'MIE;' ].pack('a8V9a4')
	end

	def self.mktoc0(privkey_pem, code, load_addr)
		key = OpenSSL::PKey::RSA.new(privkey_pem)
		cert = Certificate.new(key, OpenSSL::Digest::SHA256.digest(code))
		toc0_cert = TOC0Item.new(0x010101, cert.to_der, TOC0Item::CERTIFICATE)
		toc0_code = TOC0Item.new(0x010202, code, TOC0Item::CODE, load_addr)
		toc0 = TOC0.new( [ toc0_cert, toc0_code ] )
		toc0.to_s
	end
end
