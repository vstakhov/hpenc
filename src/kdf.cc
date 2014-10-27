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
#include <openssl/evp.h>

namespace hpenc
{

class HPEncKDF::impl {
public:
	std::unique_ptr<HPEncNonce> nonce;
	std::unique_ptr<SessionKey> psk;
	std::vector<byte> initial_nonce;
	bool password;

	impl(std::unique_ptr<SessionKey> &&_psk,
			std::unique_ptr<HPEncNonce> &&_nonce,
			bool _password) : psk(std::move(_psk)), password(_password)
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
		std::unique_ptr<HPEncNonce> &&nonce, bool password) :
	pimpl(new impl(std::move(psk), std::move(nonce), password))
{
}

HPEncKDF::~HPEncKDF()
{
}

std::shared_ptr<SessionKey> HPEncKDF::genKey(unsigned keylen)
{
	auto nonce = pimpl->nonce->incAndGet();
	auto sk = std::make_shared<SessionKey>(keylen, 0);
	const int pbkdf_iters = 65536;

	if (pimpl->password) {
		// We need to derive key from password first of all
		std::unique_ptr<SessionKey> passwd;
		std::swap(pimpl->psk, passwd);
		pimpl->psk = util::make_unique<SessionKey>();
		pimpl->psk->resize(crypto_stream_xchacha20_KEYBYTES);
		// Now derive using openssl
		PKCS5_PBKDF2_HMAC((const char*)passwd->data(), passwd->size(),
				nonce.data(), nonce.size(), pbkdf_iters, EVP_sha512(),
				 pimpl->psk->size(), pimpl->psk->data());
		pimpl->password = false;
	}
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
