/*
 * Copyright (c) 2014, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "util.h"
#include "encrypt.h"
#include "decrypt.h"
#include "kdf.h"
#include "nonce.h"
#include <unistd.h>
#include <iostream>
#include <cstdlib>
#include <sodium.h>

using namespace hpenc;

static void usage(char **argv)
{
	std::cerr 	<< "Usage: " << argv[0] << " [-h] [-d] [-a algorithm] [-k key|-p] [-l]"
				<< "[-b block_size] [-B] [-r] [-c count] [psk]"
				<< std::endl
				<< "Available options: " << std::endl
				<< "  -d                   Decrypt data" << std::endl
				<< "  -a <algorithm>       Use specified algorithm: chacha20," << std::endl
				<< "                       aes-128 or aes-256" << std::endl
				<< "  -k <key>             52 bytes hex encoded pre-shared key" << std::endl
				<< "  -p                   Read password from the terminal instead of key" << std::endl
				<< "  -l                   Use legacy pbkdf method" << std::endl
				<< "  -b <block_size>      Block size to use (default: 4K)" << std::endl
				<< "  -B                   Base64 output/input" << std::endl
				<< "  -r                   Act as pseudo-random generator" << std:: endl
				<< "  -c <count>           Process <count> of blocks (default: no limit)" << std::endl;
 	::exit(EXIT_FAILURE);
}

static AeadAlgorithm
parseAlg(const std::string &arg)
{
	if (arg.find("chacha") != std::string::npos) {
		return AeadAlgorithm::CHACHA20_POLY_1305;
	}
	else if (arg.find("256") != std::string::npos) {
		return AeadAlgorithm::AES_GCM_256;
	}

	return AeadAlgorithm::AES_GCM_128;
}

int main(int argc, char **argv)
{
	AeadAlgorithm alg = AeadAlgorithm::AES_GCM_128;
	char opt;
	unsigned block_size = 4096;
	char *err_str;
	std::unique_ptr<SessionKey> psk;
	bool encode = false;
	bool decrypt = false;
	bool random_mode = false;
	bool password = false;
	bool legacy_pbkdf = false;
	unsigned count = 0;
	unsigned nthreads = 0;

	while ((opt = ::getopt(argc, argv, "ha:b:plk:Bdn:rc:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv);
			break;
		case 'a':
			alg = parseAlg(optarg);
			break;
		case 'b':
			block_size = ::strtoul(optarg, &err_str, 10);
			if (err_str && *err_str != '\0') {
				switch (*err_str) {
				case 'K':
				case 'k':
					block_size *= 1024;
					break;
				case 'M':
				case 'm':
					block_size *= 1024 * 1024;
					break;
				default:
					usage(argv);
					break;
				}
			}
			break;
		case 'k':
		{
			if (psk) {
				std::cerr << "Key/password has been already specified"
					<< std::endl;
				exit(EXIT_FAILURE);
			}
			std::string key_base32(optarg);
			auto decoded = util::base32DecodeKey(key_base32);
			if (!decoded || decoded->size() != master_key_length) {
				usage(argv);
			}
			psk = std::move(decoded);
			break;
		}
		case 'B':
			encode = true;
			break;
		case 'd':
			decrypt = true;
			break;
		case 'n':
			nthreads = strtoul(optarg, NULL, 10);
			break;
		case 'r':
			random_mode = true;
			break;
		case 'c':
			count = strtoul(optarg, &err_str, 10);
			if (err_str && *err_str != '\0') {
				switch (*err_str) {
				case 'K':
				case 'k':
					count *= 1024;
					break;
				case 'M':
				case 'm':
					count *= 1024 * 1024;
					break;
				default:
					usage(argv);
					break;
				}
			}
			break;
		case 'p':
		{
			password = true;
			if (psk) {
				std::cerr << "Key/password has been already specified" <<
						std::endl;
				exit(EXIT_FAILURE);
			}
			auto passwd = util::readPassphrase();
			if (!passwd || passwd->size() == 0) {
				std::cerr << "Password is invalid" << std::endl;
				exit(EXIT_FAILURE);
			}
			if (passwd->size() < 6) {
				// XXX: validate it more precisely
				std::cerr << "Password is too short " <<
						"(6 characters at least are required)" << std::endl;
				exit(EXIT_FAILURE);
			}
			std::swap(psk, passwd);
			break;
		}
		case 'l':
			legacy_pbkdf = true;
			break;
		}
	}

	argv += optind;
	argc -= optind;

	if (sodium_init() != 0) {
		std::cerr << "Cannot init libsodium" << std::endl;
		exit(EXIT_FAILURE);
	}

	if (!psk) {
		if (decrypt) {
			std::cerr << "Cannot decrypt without key" << std::endl;
			exit(EXIT_FAILURE);
		}
		psk = util::genPSK(alg);

		if (!psk) {
			std::cerr << "Cannot open /dev/urandom" << std::endl;
			exit(EXIT_FAILURE);
		}

		if (!random_mode) {
			std::cerr << "Random key: " << util::base32EncodeKey(psk.get())
				  << std::endl;
		}
		// Just print key
		if (argc == 1 && std::string(argv[0]).find("psk") != std::string::npos) {
			exit(EXIT_SUCCESS);
		}
	}

	try {
		auto kdf = util::make_unique<HPEncKDF>(std::move(psk), nullptr, password,
				legacy_pbkdf);

		if (decrypt) {
			auto decrypter = util::make_unique<HPEncDecrypt>(std::move(kdf),
					std::string(""), std::string(""));
			decrypter->decrypt(encode, count);
		}
		else {
			auto encrypter = util::make_unique<HPEncEncrypt>(std::move(kdf),
				std::string(""), std::string(""),
				alg, block_size, nthreads, random_mode);
			encrypter->encrypt(encode, count);
		}
	}
	catch (std::exception &e) {
		std::cerr << "Failure: " << e.what() << std::endl;
		exit(EXIT_FAILURE);
	}

	return 0;
}
