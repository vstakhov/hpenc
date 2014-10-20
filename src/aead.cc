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

#include <crypto_onetimeauth_poly1305.h>
#include <crypto_stream_chacha20.h>
#include <crypto_verify_16.h>
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
public:
	OpenSSLAeadCipher(AeadAlgorithm _alg) : AeadCipher()
	{
		ctx_enc.reset(EVP_CIPHER_CTX_new());
		ctx_dec.reset(EVP_CIPHER_CTX_new());

		switch(_alg) {
		case AeadAlgorithm::AES_GCM_128:
			alg = EVP_aes_128_gcm();
			break;
		case AeadAlgorithm::AES_GCM_256:
			alg = EVP_aes_256_gcm();
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
		if (aadlen > 0) {
			// Add unencrypted data
			EVP_EncryptUpdate(ctx_ptr, NULL, &howmany,
					(const unsigned char*) aad, aadlen);
		}
		// Encrypt
		EVP_EncryptUpdate(ctx_ptr,(unsigned char *) out, &howmany,
				(const unsigned char *) in, inlen);
		EVP_EncryptFinal_ex(ctx_ptr, (unsigned char *) out, &howmany);
		// Get tag
		auto tag = util::make_unique < MacTag >(taglen());
		EVP_CIPHER_CTX_ctrl(ctx_ptr, EVP_CTRL_GCM_GET_TAG, 16, tag->data);

		return tag;
	}

	virtual bool decrypt(const byte *aad, size_t aadlen, const byte *nonce,
			size_t nlen, const byte *in, size_t inlen, byte *out,
			const MacTag *tag) override
	{
		int howmany = 0;
		auto ctx_ptr = ctx_enc.get();
		// Set nonce and key
		EVP_CIPHER_CTX_ctrl(ctx_ptr, EVP_CTRL_GCM_SET_IVLEN, nlen, NULL);
		EVP_EncryptInit_ex(ctx_ptr, NULL, NULL, key->data(),
				(const unsigned char*) nonce);

		// Set tag
		EVP_CIPHER_CTX_ctrl(ctx_ptr, EVP_CTRL_GCM_SET_TAG, tag->datalen,
				(void *) tag->data);
		if (aadlen > 0) {
			EVP_DecryptUpdate(ctx_ptr, NULL, &howmany,
					(const unsigned char*) aad, aadlen);
		}
		EVP_DecryptUpdate(ctx_ptr,(unsigned char *) out, &howmany,
				(const unsigned char *) in, inlen);
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
		return 8;
	}
};

class Chacha20Poly1305AeadCipher: public AeadCipher
{
private:
	crypto_onetimeauth_poly1305_state state;

	static inline void _u64_le_from_ull(unsigned char out[8U],
			unsigned long long x)
	{
		out[0] = (unsigned char) (x & 0xff);
		x >>= 8;
		out[1] = (unsigned char) (x & 0xff);
		x >>= 8;
		out[2] = (unsigned char) (x & 0xff);
		x >>= 8;
		out[3] = (unsigned char) (x & 0xff);
		x >>= 8;
		out[4] = (unsigned char) (x & 0xff);
		x >>= 8;
		out[5] = (unsigned char) (x & 0xff);
		x >>= 8;
		out[6] = (unsigned char) (x & 0xff);
		x >>= 8;
		out[7] = (unsigned char) (x & 0xff);
	}
public:
	Chacha20Poly1305AeadCipher(AeadAlgorithm _alg) :
			AeadCipher()
	{
	}

	virtual std::unique_ptr<MacTag> encrypt(const byte *aad, size_t aadlen,
			const byte *nonce, size_t nlen, const byte *in, size_t inlen,
			byte *out) override
	{

		byte block0[64];
		auto tag = util::make_unique < MacTag >(taglen());
		byte slen[8];

		// Set poly1305 key
		crypto_stream_chacha20(block0, sizeof block0, nonce, key->data());
		crypto_onetimeauth_poly1305_init(&state, block0);
		sodium_memzero(block0, sizeof block0);

		if (aadlen > 0) {
			// Add unencrypted data
			crypto_onetimeauth_poly1305_update(&state, aad, aadlen);
			_u64_le_from_ull(slen, aadlen);
			crypto_onetimeauth_poly1305_update(&state, slen, sizeof slen);
		}
		// Encrypt
		crypto_stream_chacha20_xor_ic(out, in, inlen, nonce, 1U, key->data());
		// Final tag
		crypto_onetimeauth_poly1305_update(&state, out, inlen);
		_u64_le_from_ull(slen, inlen);
		crypto_onetimeauth_poly1305_update(&state, slen, sizeof slen);
		crypto_onetimeauth_poly1305_final(&state, tag->data);
		sodium_memzero(&state, sizeof state);

		return tag;
	}

	virtual bool decrypt(const byte *aad, size_t aadlen, const byte *nonce,
			size_t nlen, const byte *in, size_t inlen, byte *out,
			const MacTag *tag) override
	{
		byte block0[64];
		byte slen[8];
		auto test_tag = util::make_unique < MacTag >(taglen());

		// Set poly1305 key
		crypto_stream_chacha20(block0, sizeof block0, nonce, key->data());
		crypto_onetimeauth_poly1305_init(&state, block0);
		sodium_memzero(block0, sizeof block0);

		if (aadlen > 0) {
			crypto_onetimeauth_poly1305_update(&state, aad, aadlen);
			_u64_le_from_ull(slen, aadlen);
			crypto_onetimeauth_poly1305_update(&state, slen, sizeof slen);
		}
		crypto_onetimeauth_poly1305_update(&state, in, inlen);
		_u64_le_from_ull(slen, inlen);
		crypto_onetimeauth_poly1305_update(&state, slen, sizeof slen);
		crypto_onetimeauth_poly1305_final(&state, test_tag->data);
		sodium_memzero(&state, sizeof state);

		auto ret = crypto_verify_16(test_tag->data, tag->data);
		if (ret != 0) {
			sodium_memzero(out, inlen);
			return false;
		}

		crypto_stream_chacha20_xor_ic(out, in, inlen, nonce, 1U, key->data());

		return true;
	}

	virtual size_t taglen() const override
	{
		return
		crypto_onetimeauth_poly1305_BYTES;
	}
	virtual size_t keylen() const override
	{
		return crypto_stream_chacha20_keybytes();
	}

	virtual size_t noncelen() const override
	{
		return crypto_stream_chacha20_noncebytes();
	}
};

class HPencAead::impl
{
public:
	std::unique_ptr<AeadCipher> cipher;

	impl(AeadAlgorithm alg)
	{
		if (alg == AeadAlgorithm::AES_GCM_128
				|| alg == AeadAlgorithm::AES_GCM_256) {
			cipher.reset(new OpenSSLAeadCipher(alg));
		}
		else if (alg == AeadAlgorithm::CHACHA20_POLY_1305) {
			cipher.reset(new Chacha20Poly1305AeadCipher(alg));
		}
	}

	virtual ~impl()
	{
	}
};

HPencAead::HPencAead(AeadAlgorithm alg) :
		pimpl(new impl(alg))
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
