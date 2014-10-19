/* Copyright (c) 2014, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#ifndef AEAD_H_
#define AEAD_H_

#include <memory>
#include <vector>
#include <string>

namespace hpenc
{

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

/*
 * Authenticated encryption with additional data
 */

struct MacTag {
	byte *data;
	size_t datalen;
	bool allocated;

	MacTag() : data(nullptr), datalen(0), allocated(false) {}
	explicit MacTag(size_t len)
	{
		data = new (std::nothrow) byte[len];
		if (data != nullptr) {
			datalen = len;
			allocated = true;
		}
	}
	virtual ~MacTag()
	{
		if (datalen > 0 && allocated) {
			delete [] data;
		}
	}
};

class HPencAead {
private:
	class impl;
	std::unique_ptr<impl> pimpl;
public:
	explicit HPencAead(AeadAlgorithm alg = AeadAlgorithm::AES_GCM_128);
	virtual ~HPencAead();

	void setKey(std::unique_ptr<SessionKey> &&sk);
	virtual std::unique_ptr<MacTag> encrypt(const byte *aad, size_t aadlen,
			const byte *nonce, size_t nlen,
			const byte *in, size_t inlen,
			byte *out);
	virtual bool decrypt(
			const byte *aad, size_t aadlen,
			const byte *nonce, size_t nlen,
			const byte *in, size_t inlen,
			const MacTag *tag,
			byte *out);
	size_t taglen() const;
	size_t keylen() const;
	size_t noncelen() const;
};

} /* namespace penc */

#endif /* AEAD_H_ */
