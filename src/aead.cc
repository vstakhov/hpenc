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
#include <array>
#include <stdexcept>
#include "aead.h"
#include "util.h"

namespace hpenc
{

// Basic class for aead alorithms
class AeadCipher
{
protected:
	std::shared_ptr<SessionKey> key;
	bool random_mode;
public:
	AeadCipher(bool _random_mode = false) : random_mode(_random_mode) {}
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
	EVP_CIPHER_CTX *ctx_enc;
	EVP_CIPHER_CTX *ctx_dec;
	const EVP_CIPHER *alg;
	AeadAlgorithm alg_num;
public:
	OpenSSLAeadCipher(AeadAlgorithm _alg, bool _rm)
		: AeadCipher(_rm)
	{
		ctx_enc = EVP_CIPHER_CTX_new();
		ctx_dec = EVP_CIPHER_CTX_new();

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
		EVP_EncryptInit_ex(ctx_enc, alg, NULL, NULL, NULL);
		EVP_DecryptInit_ex(ctx_dec, alg, NULL, NULL, NULL);

		alg_num = _alg;
	}

  virtual ~OpenSSLAeadCipher() 
  {
    EVP_CIPHER_CTX_free(ctx_enc);
    EVP_CIPHER_CTX_free(ctx_dec);
  }

	virtual std::unique_ptr<MacTag> encrypt(const byte *aad, size_t aadlen,
			const byte *nonce, size_t nlen, const byte *in, size_t inlen,
			byte *out) override
	{
		int howmany = 0;
		auto ctx_ptr = ctx_enc;

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
		auto ctx_ptr = ctx_enc;
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
public:
	Chacha20Poly1305AeadCipher(AeadAlgorithm _alg, bool _rm) :
			AeadCipher(_rm)
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

#if defined(_M_AMD64) || defined(__x86_64__) || defined(__amd64__)
#if defined(_MSC_VER) && _MSC_VER >= 1600 || (defined(__GNUC__) && !defined(__clang__))
#define HW_TIAOXIN 1

#pragma GCC push_options
#pragma GCC target("ssse3,aes")

#include <tmmintrin.h>
#include <wmmintrin.h>


class Tiaoxin346AeadCipherOpt: public AeadCipher
{
private:
	__m128i T3[3], T4[4], T6[6];
	__m128i K;
	__m128i N;
	__m128i Z0;
	__m128i Z1;
	__m128i SH;

	void init(const byte *nonce, size_t nlen)
	{
		K = _mm_load_si128((const __m128i *)key->data());
		N = _mm_load_si128((const __m128i *)nonce);

		T3[0] = K; T3[1] = K; T3[2] = N;
		T4[0] = K; T4[1] = K; T4[2] = N; T4[3] = Z0;
		T6[0] = K; T6[1] = K; T6[2] = N; T6[3] = Z1;
		T6[4] = T6[5] = _mm_xor_si128(Z0, Z0);

		for (auto i = 0; i < 15; i ++) {
			update(Z0, Z1, Z0);
		}
	}

	inline void r1(__m128i M)
	{
		auto tmp = T3[0];

		T3[0] = _mm_aesenc_si128(T3[2], M);
		T3[2] = T3[1];
		T3[1] = _mm_aesenc_si128(tmp, Z0);
		T3[0] = _mm_xor_si128(T3[0], tmp);
	}

	inline void r2(__m128i M)
	{
		auto tmp = T4[0];

		T4[0] = _mm_aesenc_si128(T4[3], M);
		T4[3] = T4[2];
		T4[2] = T4[1];
		T4[1] = _mm_aesenc_si128(tmp, Z0);
		T4[0] = _mm_xor_si128(T4[0], tmp);
	}

	inline void r3(__m128i M)
	{
		auto tmp = T6[0];

		T6[0] = _mm_aesenc_si128(T6[5], M);
		T6[5] = T6[4];
		T6[4] = T6[3];
		T6[3] = T6[2];
		T6[2] = T6[1];
		T6[1] = _mm_aesenc_si128(tmp, Z0);
		T6[0] = _mm_xor_si128(T6[0], tmp);
	}

	inline void update(__m128i M0, __m128i M1, __m128i M2)
	{
		r1(M0);
		r2(M1);
		r3(M2);
	}

	inline void store1(byte *c, off_t offset)
	{
		auto O = _mm_xor_si128(T4[1], _mm_xor_si128(T3[0],
				_mm_xor_si128(T3[2], _mm_and_si128(T6[3], T4[3]))
		));
		_mm_storeu_si128((__m128i *)(c + offset), O);
	}


	inline void store2(byte *c, off_t offset)
	{
		auto O = _mm_xor_si128(T3[1], _mm_xor_si128(T6[0],
				_mm_xor_si128(T4[2], _mm_and_si128(T6[5], T3[2]))
		));
		_mm_storeu_si128((__m128i *)(c + offset), O);
	}

	inline void decrypt_round(__m128i C0, __m128i C1, byte *b1, byte *b2)
	{
		/* Modified update */
		auto Mtmp0 = _mm_aesenc_si128(T3[2], T3[0]);
		auto Mtmp1 = _mm_aesenc_si128(T6[5], T6[0]);
		auto Mtmp2 = _mm_aesenc_si128(T4[3], T4[0]);

		T3[2] = T3[1];
		T3[1] = _mm_aesenc_si128(T3[0], Z0);

		T4[3] = T4[2];
		T4[2] = T4[1];
		T4[1] = _mm_aesenc_si128(T4[0], Z0);

		T6[5] = T6[4];
		T6[4] = T6[3];
		T6[3] = T6[2];
		T6[2] = T6[1];
		T6[1] = _mm_aesenc_si128(T6[0], Z0);

		T3[0] = _mm_xor_si128(C0, _mm_xor_si128(T3[2], _mm_xor_si128(T4[1],
				_mm_and_si128(T6[3], T4[3]))));
		auto M0 = _mm_xor_si128(Mtmp0, T3[0]);
		T6[0] = _mm_xor_si128(C1, _mm_xor_si128(T4[2], _mm_xor_si128(T3[1],
				_mm_and_si128(T6[5], T3[2]))));
		auto M1 = _mm_xor_si128(Mtmp1, _mm_xor_si128(T6[0], M0));
		T4[0] = _mm_xor_si128(Mtmp2, M1);

		_mm_storeu_si128((__m128i *)b1, M0);
		_mm_storeu_si128((__m128i *)b2, M1);
	}


	void finish(uint64_t aadlen, uint64_t inlen,
			std::unique_ptr<MacTag> &tag)
	{
		__m128i W0, W1, Wt, T;

		W0 = _mm_set_epi64x(0, aadlen);
		W1 = _mm_set_epi64x(0, inlen);
		W0 = _mm_shuffle_epi8(W0, SH);
		W1 = _mm_shuffle_epi8(W1, SH);
		Wt = _mm_xor_si128(W0, W1);
		update(W0, W1, Wt);

		for (auto i = 0; i < 20; i ++) {
			update(Z0, Z1, Z0);
		}

		T = _mm_xor_si128(T3[0], _mm_xor_si128(T3[1],
				_mm_xor_si128(T3[2], _mm_xor_si128(T4[0],
					_mm_xor_si128(T4[1], _mm_xor_si128(T4[2],
						_mm_xor_si128(T4[3],
							_mm_xor_si128(T6[0],
								_mm_xor_si128(T6[1],
									_mm_xor_si128(T6[2],
										_mm_xor_si128(T6[3],
											_mm_xor_si128(T6[4], T6[5]))))))))))));
		_mm_storeu_si128((__m128i *)tag->data, T);
	}

public:
	Tiaoxin346AeadCipherOpt(AeadAlgorithm _alg, bool _rm) :
			AeadCipher(_rm)
	{
		Z0 = _mm_set_epi8(0x42,0x8a,0x2f,0x98,0xd7,0x28,0xae,0x22,0x71,0x37,
				0x44,0x91,0x23,0xef,0x65,0xcd);
		Z1 = _mm_set_epi8(0xb5,0xc0,0xfb,0xcf,0xec,0x4d,0x3b,0x2f,0xe9,0xb5,
				0xdb,0xa5,0x81,0x89,0xdb,0xbc);
		K = _mm_xor_si128(Z0, Z0);
		N = _mm_xor_si128(Z0, Z0);
		/* Convert length to __m128i */
		SH = _mm_set_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	}

	virtual std::unique_ptr<MacTag> encrypt(const byte *aad, size_t aadlen,
			const byte *nonce, size_t nlen, const byte *in, size_t inlen,
			byte *out) override
	{

		__m128i M0, M1, M2, M3, tmp;
		alignas(32) std::array<byte, 32> padded;

		if (!random_mode) {
			auto tag = util::make_unique < MacTag >(taglen());
			decltype(aadlen) i;
			init(nonce, nlen);

			for (i = 0; i + 64 <= aadlen; i += 64) {
				M0 = _mm_load_si128 ((const __m128i *)(aad + i));
				M1 = _mm_load_si128 ((const __m128i *)(aad + i + 16));
				tmp = _mm_xor_si128 (M0, M1);
				update(M0, M1, tmp);
				M2 = _mm_load_si128 ((const __m128i *)(aad + i + 32));
				M3 = _mm_load_si128 ((const __m128i *)(aad + i + 48));
				tmp = _mm_xor_si128 (M2, M3);
				update(M2, M3, tmp);
			}
			for (; i + 32 <= aadlen; i += 32) {
				M0 = _mm_load_si128 ((const __m128i *)(aad + i));
				M1 = _mm_load_si128 ((const __m128i *)(aad + i + 16));
				tmp = _mm_xor_si128 (M0, M1);
				update(M0, M1, tmp);
			}

			if (aadlen > i) {
				padded.fill(0);
				::memcpy(padded.data(), aad + i, aadlen - i);
				M0 = _mm_load_si128 ((const __m128i *)(padded.data()));
				M1 = _mm_load_si128 ((const __m128i *)(padded.data() + 16));
				tmp = _mm_xor_si128 (M0, M1);
				update(M0, M1, tmp);
			}

			/* Encryption stage */
			for (i = 0; i + 64 <= inlen; i += 64) {
				M0 = _mm_load_si128 ((const __m128i *)(in + i));
				M1 = _mm_load_si128 ((const __m128i *)(in + i + 16));
				tmp = _mm_xor_si128 (M0, M1);
				update(M0, M1, tmp);
				store1(out, i);
				store2(out, i + 16);
				M2 = _mm_load_si128 ((const __m128i *)(in + i + 32));
				M3 = _mm_load_si128 ((const __m128i *)(in + i + 48));
				tmp = _mm_xor_si128 (M2, M3);
				update(M2, M3, tmp);
				store1(out, i + 32);
				store2(out, i + 48);
			}
			for (; i + 32 <= inlen; i += 32) {
				M0 = _mm_load_si128 ((const __m128i *)(in + i));
				M1 = _mm_load_si128 ((const __m128i *)(in + i + 16));
				tmp = _mm_xor_si128 (M0, M1);
				update(M0, M1, tmp);
				store1(out, i);
				store2(out, i + 16);
			}

			if (inlen > i) {
				padded.fill(0);
				::memcpy(padded.data(), in + i, inlen - i);
				M2 = _mm_load_si128 ((const __m128i *)(padded.data()));
				M3 = _mm_load_si128 ((const __m128i *)(padded.data() + 16));
				tmp = _mm_xor_si128 (M2, M3);
				update(M2, M3, tmp);
				store1(padded.data(), 0);
				store2(padded.data(), 16);
				::memcpy(out + i, padded.data(), inlen - i);
			}

			finish(aadlen, inlen, tag);

			return tag;
		}
		else {
			/* In random mode we can just use aes-ctr */
			throw std::runtime_error("Tiaoxin does not support random mode");
		}
	}

	virtual bool decrypt(const byte *aad, size_t aadlen, const byte *nonce,
			size_t nlen, const byte *in, size_t inlen, byte *out,
			const MacTag *tag) override
	{
		__m128i M0, M1, M2, M3, tmp;
		alignas(32) std::array<byte, 32> padded;

		auto test_tag = util::make_unique < MacTag >(taglen());
		decltype(aadlen) i;
		init(nonce, nlen);

		for (i = 0; i + 64 <= aadlen; i += 64) {
			M0 = _mm_load_si128 ((const __m128i *)(aad + i));
			M1 = _mm_load_si128 ((const __m128i *)(aad + i + 16));
			tmp = _mm_xor_si128 (M0, M1);
			update(M0, M1, tmp);
			M2 = _mm_load_si128 ((const __m128i *)(aad + i + 32));
			M3 = _mm_load_si128 ((const __m128i *)(aad + i + 48));
			tmp = _mm_xor_si128 (M2, M3);
			update(M2, M3, tmp);
		}
		for (; i + 32 <= aadlen; i += 32) {
			M0 = _mm_load_si128 ((const __m128i *)(aad + i));
			M1 = _mm_load_si128 ((const __m128i *)(aad + i + 16));
			tmp = _mm_xor_si128 (M0, M1);
			update(M0, M1, tmp);
		}

		if (aadlen > i) {
			padded.fill(0);
			::memcpy(padded.data(), aad + i, aadlen - i);
			M2 = _mm_load_si128 ((const __m128i *)(padded.data()));
			M3 = _mm_load_si128 ((const __m128i *)(padded.data() + 16));
			tmp = _mm_xor_si128 (M2, M3);
			update(M2, M3, tmp);
		}

		/* Decryption stage */
		for (i = 0; i + 64 <= inlen; i += 64) {
			M0 = _mm_load_si128 ((const __m128i *)(in + i));
			M1 = _mm_load_si128 ((const __m128i *)(in + i + 16));
			decrypt_round(M0, M1, out + i, out + i + 16);
			M2 = _mm_load_si128 ((const __m128i *)(in + i + 32));
			M3 = _mm_load_si128 ((const __m128i *)(in + i + 48));
			decrypt_round(M2, M3, out + i + 32, out + i + 48);
		}

		for (; i + 32 <= inlen; i += 32) {
#if 0
			tmp = _mm_xor_si128(Z0, Z0);
			M0 = _mm_load_si128 ((const __m128i *)(in + i));
			M1 = _mm_load_si128 ((const __m128i *)(in + i + 16));
			update(tmp, tmp, tmp);
			auto D0 = _mm_xor_si128(M0, _mm_xor_si128(T3[0],
					_mm_xor_si128(T3[2], _mm_xor_si128(T4[1],
							_mm_and_si128(T6[3], T4[3])))));
			auto D1 = _mm_xor_si128(M0, _mm_xor_si128(T6[0],
					_mm_xor_si128(T4[2], _mm_xor_si128(T3[1],
						_mm_xor_si128(_mm_and_si128(T6[5], T3[2]), D0)))));
			T3[0] = _mm_xor_si128(T3[0], D0);
			T4[0] = _mm_xor_si128(T4[0], D0);
			T6[0] = _mm_xor_si128(T6[0], _mm_xor_si128(D0, D1));
			_mm_storeu_si128((__m128i *)(out + i), D0);
			_mm_storeu_si128((__m128i *)(out + i + 16), D1);
#endif
			M0 = _mm_load_si128 ((const __m128i *)(in + i));
			M1 = _mm_load_si128 ((const __m128i *)(in + i + 16));
			decrypt_round(M0, M1, out + i, out + i + 16);
		}

		if (inlen > i) {
			padded.fill(0);
			::memcpy(padded.data(), in + i, inlen - i);
			tmp = _mm_xor_si128(Z0, Z0);
			M0 = _mm_load_si128 ((const __m128i *)(padded.data()));
			M1 = _mm_load_si128 ((const __m128i *)(padded.data() + 16));

			update(tmp, tmp, tmp);

			auto D0 = _mm_xor_si128(M0, _mm_xor_si128(T3[0],
					_mm_xor_si128(T3[2], _mm_xor_si128(T4[1],
							_mm_and_si128(T6[3], T4[3])))));
			if (inlen  - i <= 16 ){
				_mm_storeu_si128((__m128i *)(padded.data()), D0);
				::memset(padded.data() + (inlen  - i), 0,  16 - (inlen  - i));
				D0 = _mm_load_si128 ((const __m128i *)(padded.data()));
			}

			auto D1 = _mm_xor_si128(M1, _mm_xor_si128(T6[0],
					_mm_xor_si128(T4[2], _mm_xor_si128(T3[1],
							_mm_xor_si128(_mm_and_si128(T6[5], T3[2]), D0)))));
			if (inlen - i > 16) {
				_mm_storeu_si128((__m128i *)padded.data(), D1);
				::memset(padded.data() + (inlen  - i - 16), 0, 32 - (inlen - i));
				D1 = _mm_load_si128 ((const __m128i *)(padded.data()));
			}
			else{
				D1 = tmp;
			}

			T3[0] = _mm_xor_si128(T3[0], D0);
			T4[0] = _mm_xor_si128(T4[0], D1);
			T6[0] = _mm_xor_si128(T6[0], _mm_xor_si128(D0, D1));
			_mm_storeu_si128((__m128i *)(padded.data()), D0);
			_mm_storeu_si128((__m128i *)(padded.data() + 16), D1);

			::memcpy(out + i, padded.data(), inlen - i);
		}

		finish(aadlen, inlen, test_tag);

		return sodium_memcmp(tag->data, test_tag->data, tag->datalen) == 0;
	}

	virtual size_t taglen() const override
	{
		return 16;
	}
	virtual size_t keylen() const override
	{
		return 16;
	}

	virtual size_t noncelen() const override
	{
		return 16;
	}
};

#pragma GCC pop_options
#endif
#endif

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
		else if (alg == AeadAlgorithm::TIAOXIN_346) {
#ifdef HW_TIAOXIN
			if (sodium_runtime_has_aesni()) {
				cipher.reset(new Tiaoxin346AeadCipherOpt(alg, random_mode));
			}
      else {
        // XXX: add some warning
			  cipher.reset(new OpenSSLAeadCipher(AeadAlgorithm::AES_GCM_128, random_mode));
      }
#else
    // XXX: add some warning
		cipher.reset(new OpenSSLAeadCipher(AeadAlgorithm::AES_GCM_128, random_mode));
#endif
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
