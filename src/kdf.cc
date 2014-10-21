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
#include "kdf.h"
#include "nonce.h"
#include "util.h"
#include <crypto_stream_chacha20.h>

namespace hpenc
{

class HPEncKDF::impl {
public:
	std::unique_ptr<HPEncNonce> nonce;
	std::unique_ptr<SessionKey> psk;
	std::vector<byte> initial_nonce;

	impl(std::unique_ptr<SessionKey> &&_psk,
			std::unique_ptr<HPEncNonce> &&_nonce) : psk(std::move(_psk))
	{
		if (!_nonce) {
			// Create random nonce
			nonce.reset(new HPEncNonce(crypto_stream_xchacha20_NONCEBYTES));
			if (!nonce->randomize()) {
				throw std::runtime_error("Cannot create random nonce");
			}
		}
		else {
			if (_nonce->size() != crypto_stream_xchacha20_NONCEBYTES) {
				throw std::runtime_error("Invalid nonce specified");
			}
			nonce.swap(_nonce);
		}

		// Save the initial nonce
		initial_nonce = nonce->get();
	}
};

HPEncKDF::HPEncKDF(std::unique_ptr<SessionKey> &&psk,
		std::unique_ptr<HPEncNonce> &&nonce) :
	pimpl(new impl(std::move(psk), std::move(nonce)))
{
}

HPEncKDF::~HPEncKDF()
{
}

std::shared_ptr<SessionKey> HPEncKDF::genKey(unsigned keylen)
{
	auto nonce = pimpl->nonce->incAndGet();
	auto sk = std::make_shared<SessionKey>(keylen, 0);

	crypto_stream_xchacha20(sk->data(), sk->size(), nonce.data(),
		pimpl->psk->data());

	return sk;
}

const std::vector<byte>& HPEncKDF::initialNonce() const
{
	return pimpl->initial_nonce;
}

void HPEncKDF::setNonce(const std::vector<byte> &nonce)
{
	auto n = util::make_unique<HPEncNonce>(nonce);
	if (n->size() != crypto_stream_xchacha20_NONCEBYTES) {
		throw std::runtime_error("Invalid nonce specified");
	}

	pimpl->nonce.swap(n);
}

} /* namespace hpenc */
