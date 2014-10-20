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
#ifndef COMMON_H_
#define COMMON_H_

#include <memory>
#include <vector>
#include <cstddef>

namespace hpenc {

using byte = unsigned char;
using SessionKey = std::vector<byte>;

enum class AeadAlgorithm {
	AES_GCM_128 = 0,
	AES_GCM_256,
	CHACHA20_POLY_1305
};

static const int AeadKeyLengths[] = {
	16,	// AES_GCM_128
	32, // AES_GCM_256
	32 // CHACHA20_POLY1305
};

// Maximum is 16 megabytes block
const unsigned max_block = 16 * 1024 * 1024;

const unsigned master_key_length = 32; // CHACHA20_POLY1305

struct HPEncHeader {
	AeadAlgorithm alg;
	unsigned blen;

	HPEncHeader(AeadAlgorithm _alg, unsigned _blen) : alg(_alg), blen(_blen) {}
	bool toFd(int fd, bool encode = false);

	static std::unique_ptr<HPEncHeader> fromFd(int fd, bool encode = false);
};

constexpr static const unsigned rekey_blocks = 1024;

}


#endif /* COMMON_H_ */
