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

#include <openssl/evp.h>

#include <sodium.h>
#include <cstring>
#include "aead.h"
#include "util.h"

namespace hpenc
{

// Basic class for aead alorithms
class AeadCipher
{
protected:
	std::shared_ptr<SessionKey> key;
public:
	AeadCipher() {}
	virtual ~AeadCipher() {}

	virtual bool hasKey() const { return !!key; }
	virtual void setKey(std::shared_ptr<SessionKey> const &_key) { key = _key; }

	virtual std::unique_ptr<MacTag> encrypt(const byte *aad, size_t aadlen,
			const byte *nonce, size_t nlen, const byte *in, size_t inlen,
			byte *out) = 0;
	virtual bool decrypt(const byte *aad, size_t aadlen, const byte *nonce,
			size_t nlen, const byte *in, size_t inlen, byte *out,
			const MacTag *tag) = 0;
	virtual size_t taglen() const
	{
		return 0;
	}
	virtual size_t keylen() const
	{
		return 0;
	}
	virtual size_t noncelen() const
	{
		return 0;
	}
};

class OpenSSLAeadCipher: public AeadCipher
{
private:
	std::unique_ptr<EVP_CIPHER_CTX> ctx_enc;
	std::unique_ptr<EVP_CIPHER_CTX> ctx_dec;
	const EVP_CIPHER *alg;
	AeadAlgorithm alg_num;
	bool random_mode;
public:
	OpenSSLAeadCipher(AeadAlgorithm _alg, bool _rm)
		: AeadCipher(), random_mode(_rm)
	{
		ctx_enc.reset(EVP_CIPHER_CTX_new());
		ctx_dec.reset(EVP_CIPHER_CTX_new());

		switch(_alg) {
		case AeadAlgorithm::AES_GCM_128:
			alg = _rm ? EVP_aes_128_ctr() : EVP_aes_128_gcm();
			break;
		case AeadAlgorithm::AES_GCM_256:
			alg = _rm ? EVP_aes_256_ctr() : EVP_aes_256_gcm();
			break;
		default:
			alg = nullptr;
			break;
		}
		EVP_EncryptInit_ex(ctx_enc.get(), alg, NULL, NULL, NULL);
		EVP_DecryptInit_ex(ctx_dec.get(), alg, NULL, NULL, NULL);

		alg_num = _alg;
	}

	virtual std::unique_ptr<MacTag> encrypt(const byte *aad, size_t aadlen,
			const byte *nonce, size_t nlen, const byte *in, size_t inlen,
			byte *out) override
	{
		int howmany = 0;
		auto ctx_ptr = ctx_enc.get();

		// Set nonce length
		EVP_CIPHER_CTX_ctrl(ctx_ptr, EVP_CTRL_GCM_SET_IVLEN, nlen, NULL);
		EVP_EncryptInit_ex(ctx_ptr, NULL, NULL, key->data(),
				(const unsigned char*) nonce);
		if (!random_mode && aadlen > 0) {
			// Add unencrypted data
			EVP_EncryptUpdate(ctx_ptr, NULL, &howmany,
					(const unsigned char*) aad, aadlen);
		}
		// Encrypt
		EVP_EncryptUpdate(ctx_ptr,(unsigned char *) out, &howmany,
				(const unsigned char *) in, inlen);
		EVP_EncryptFinal_ex(ctx_ptr, (unsigned char *) out, &howmany);
		// Get tag
		if (!random_mode) {
			auto tag = util::make_unique < MacTag >(taglen());
			EVP_CIPHER_CTX_ctrl(ctx_ptr, EVP_CTRL_GCM_GET_TAG, 16, tag->data);

			return tag;
		}

		return nullptr;
	}

	virtual bool decrypt(const byte *aad, size_t aadlen, const byte *nonce,
			size_t nlen, const byte *in, size_t inlen, byte *out,
			const MacTag *tag) override
	{
		int howmany = 0;
		auto ctx_ptr = ctx_enc.get();
		// Set nonce and key
		EVP_CIPHER_CTX_ctrl(ctx_ptr, EVP_CTRL_GCM_SET_IVLEN, nlen, NULL);
		EVP_DecryptInit_ex(ctx_ptr, NULL, NULL, key->data(),
				(const unsigned char*) nonce);

		if (aadlen > 0) {
			EVP_DecryptUpdate(ctx_ptr, NULL, &howmany,
					(const unsigned char*) aad, aadlen);
		}
		EVP_DecryptUpdate(ctx_ptr,(unsigned char *) out, &howmany,
				(const unsigned char *) in, inlen);
		// Set tag
		EVP_CIPHER_CTX_ctrl(ctx_ptr, EVP_CTRL_GCM_SET_TAG, tag->datalen,
				(void *) tag->data);
		auto res = EVP_DecryptFinal_ex(ctx_ptr,(unsigned char *) out,
				&howmany);

		return res > 0;
	}

	virtual size_t taglen() const override
	{
		return 16;
	}

	virtual size_t keylen() const override
	{
		switch(alg_num) {
		case AeadAlgorithm::AES_GCM_128:
			return 128 / 8;
		case AeadAlgorithm::AES_GCM_256:
			return 256 / 8;
		default:
			return 0;
		}
	}

	virtual size_t noncelen() const override
	{
		return 12;
	}
};

class Chacha20Poly1305AeadCipher: public AeadCipher
{
private:
	bool random_mode;

public:
	Chacha20Poly1305AeadCipher(AeadAlgorithm _alg, bool _rm) :
			AeadCipher(), random_mode(_rm)
	{
	}

	virtual std::unique_ptr<MacTag> encrypt(const byte *aad, size_t aadlen,
			const byte *nonce, size_t nlen, const byte *in, size_t inlen,
			byte *out) override
	{

		if (!random_mode) {
			auto tag = util::make_unique < MacTag >(taglen());
			crypto_aead_chacha20poly1305_encrypt_detached(out, tag->data,
					NULL, in, inlen, aad, aadlen,
					NULL, nonce, key->data());

			return tag;
		}
		else {
			/* Just generate encrypted data */
			crypto_stream_chacha20(out, inlen, nonce, key->data());

			return nullptr;
		}
	}

	virtual bool decrypt(const byte *aad, size_t aadlen, const byte *nonce,
			size_t nlen, const byte *in, size_t inlen, byte *out,
			const MacTag *tag) override
	{
		if (crypto_aead_chacha20poly1305_encrypt_detached(out, tag->data, NULL,
				in, inlen, aad, aadlen, NULL, nonce, key->data()) != 0) {
			return false;
		}

		return true;
	}

	virtual size_t taglen() const override
	{
		return crypto_aead_chacha20poly1305_abytes();
	}
	virtual size_t keylen() const override
	{
		return crypto_aead_chacha20poly1305_keybytes();
	}

	virtual size_t noncelen() const override
	{
		return crypto_aead_chacha20poly1305_npubbytes();
	}
};

class HPencAead::impl
{
public:
	std::unique_ptr<AeadCipher> cipher;

	impl(AeadAlgorithm alg, bool random_mode)
	{
		if (alg == AeadAlgorithm::AES_GCM_128
				|| alg == AeadAlgorithm::AES_GCM_256) {
			cipher.reset(new OpenSSLAeadCipher(alg, random_mode));
		}
		else if (alg == AeadAlgorithm::CHACHA20_POLY_1305) {
			cipher.reset(new Chacha20Poly1305AeadCipher(alg, random_mode));
		}
	}

	virtual ~impl()
	{
	}
};

HPencAead::HPencAead(AeadAlgorithm alg, bool random_mode) :
		pimpl(new impl(alg, random_mode))
{
}

HPencAead::~HPencAead()
{
}

void HPencAead::setKey(std::shared_ptr<SessionKey> const &sk)
{
	if (pimpl->cipher) {
		pimpl->cipher->setKey(sk);
	}
}

std::unique_ptr<MacTag> HPencAead::encrypt(const byte *aad, size_t aadlen,
		const byte *nonce, size_t nlen, const byte *in, size_t inlen, byte *out)
{
	if (!pimpl->cipher || !pimpl->cipher->hasKey()) {
		return nullptr;
	}

	return pimpl->cipher->encrypt(aad, aadlen, nonce, nlen, in, inlen, out);

}
bool HPencAead::decrypt(const byte *aad, size_t aadlen, const byte *nonce,
		size_t nlen, const byte *in, size_t inlen, const MacTag *tag, byte *out)
{
	if (!pimpl->cipher || !pimpl->cipher->hasKey()) {
		return false;
	}

	return pimpl->cipher->decrypt(aad, aadlen, nonce, nlen, in, inlen, out,
			tag);
}

size_t HPencAead::taglen() const
{
	if (!pimpl->cipher) {
		return 0;
	}

	return pimpl->cipher->taglen();
}

size_t HPencAead::keylen() const
{
	if (!pimpl->cipher) {
		return 0;
	}

	return pimpl->cipher->keylen();
}

size_t HPencAead::noncelen() const
{
	if (!pimpl->cipher) {
		return 0;
	}

	return pimpl->cipher->noncelen();
}

} /* namespace shush */
