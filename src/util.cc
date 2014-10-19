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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "util.h"
#include "aead.h"

static const char b32[]="ybndrfg8ejkmcpqxot1uwisza345h769";

using namespace hpenc;

std::string
hpenc::util::base32EncodeKey(const SessionKey *in)
{
	unsigned int i, r, x;
	auto input = in->data();
	auto len = in->size();

	int remain = -1;
	std::string result;

	result.resize(len * 8 / 5 + 1);

	for (i = 0, r = 0; i < len; i++) {
		switch (i % 5) {
		case 0:
			/* 8 bits of input and 3 to remain */
			x = input[i];
			remain = input[i] >> 5;
			result[r++] = b32[x & 0x1F];
			break;
		case 1:
			/* 11 bits of input, 1 to remain */
			x = remain | input[i] << 3;
			result[r++] = b32[x & 0x1F];
			result[r++] = b32[x >> 5 & 0x1F];
			remain = x >> 10;
			break;
		case 2:
			/* 9 bits of input, 4 to remain */
			x = remain | input[i] << 1;
			result[r++] = b32[x & 0x1F];
			remain = x >> 5;
			break;
		case 3:
			/* 12 bits of input, 2 to remain */
			x = remain | input[i] << 4;
			result[r++] = b32[x & 0x1F];
			result[r++] = b32[x >> 5 & 0x1F];
			remain = x >> 10 & 0x3;
			break;
		case 4:
			/* 10 bits of output, nothing to remain */
			x = remain | input[i] << 2;
			result[r++] = b32[x & 0x1F];
			result[r++] = b32[x >> 5 & 0x1F];
			remain = -1;
			break;
		default:
			/* Not to be happen */
			break;
		}

	}
	if (remain >= 0)
		result[r++] = b32[remain];

	return result;
}

static const char *randomdev = "/dev/urandom";

std::unique_ptr<SessionKey>
hpenc::util::genPSK(AeadAlgorithm alg)
{
	unsigned len = AeadKeyLengths[static_cast<int>(AeadAlgorithm::CHACHA20_POLY_1305)];

	auto res = util::make_unique<SessionKey>();
	res->resize(len);

	auto rnd = open(randomdev, O_RDONLY);

	if (rnd == -1) {
		return nullptr;
	}
	if (::read(rnd, res->data(), len) == -1) {
		::close(rnd);
		return nullptr;
	}

	::close(rnd);

	return std::move(res);
}
