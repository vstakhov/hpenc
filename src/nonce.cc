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

#include <sodium.h>
#include "nonce.h"
#include "aead.h"

namespace hpenc
{

class HPEncNonce::impl {
public:
	std::vector<byte> nonce;

	impl(unsigned len)
	{
		nonce.resize(len);
		nonce.assign(len, '\0');
	}

	impl(const std::vector<byte> &init)
	{
		nonce.assign(init.begin(), init.end());
	}

	void inc()
	{
		for (auto &c: nonce) {
			if (c != 0xff) {
				c ++;
				break;
			}
			else {
				// Go to the next digit
				c = 0;
			}
		}
	}
};

HPEncNonce::HPEncNonce(unsigned len) : pimpl(new impl(len))
{
}

HPEncNonce::HPEncNonce(const std::vector<byte> &init) : pimpl(new impl(init))
{
}

HPEncNonce::~HPEncNonce()
{
}

const std::vector<unsigned char>& HPEncNonce::incAndGet()
{
	pimpl->inc();
	return pimpl->nonce;
}

const std::vector<unsigned char>& HPEncNonce::get()
{
	return pimpl->nonce;
}

bool HPEncNonce::randomize()
{
	randombytes_buf(pimpl->nonce.data(), pimpl->nonce.size());

	return true;
}

unsigned HPEncNonce::size() const
{
	return pimpl->nonce.size();
}

} /* namespace hpenc */
