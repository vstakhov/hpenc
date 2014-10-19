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
#include "kdf.h"
#include <unistd.h>
#include <iostream>
#include <cstdlib>

using namespace hpenc;

static void usage(char **argv)
{
	std::cerr 	<< "Usage: " << argv[0] << " [-h] [-a algorithm] [-k key] [psk]"
				<< std::endl;
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

	while ((opt = ::getopt(argc, argv, "ha:b:")) != -1) {
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
		}
	}

	argv += optind;
	argc -= optind;

	auto psk = util::genPSK(alg);
	if (argc == 1 && std::string(argv[0]).find("psk") != std::string::npos) {
		std::cout << util::base32EncodeKey(psk.get()) << std::endl;
	}

	auto kdf = util::make_unique<HPEncKDF>(std::move(psk));
	auto encrypter = util::make_unique<HPEncEncrypt>(std::move(kdf), "", "", alg,
			block_size);

	encrypter->encrypt();

	return 0;
}
