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
#include <iostream>
#include <cerrno>
#include <cstring>
#include <arpa/inet.h>
#include "decrypt.h"
#include "nonce.h"
#include "aead.h"
#include "util.h"
#include "kdf.h"
#include "thread_pool.h"

namespace hpenc
{

class HPEncDecrypt::impl {
public:
	std::unique_ptr<HPEncKDF> kdf;
	std::unique_ptr<HPEncNonce> nonce;
	int fd_in, fd_out;
	unsigned block_size;
	std::vector<std::shared_ptr <std::vector<byte> > > io_bufs;
	std::vector <std::shared_ptr<HPencAead> > ciphers;
	bool encode;
	std::unique_ptr<ThreadPool> pool;

	impl(std::unique_ptr<HPEncKDF> &&_kdf,
		const std::string &in,
		const std::string &out,
		unsigned nthreads = 0) : kdf(std::move(_kdf)), block_size(0)
	{
		if (!in.empty()) {
			fd_in = open(in.c_str(), O_RDONLY);
			if (fd_in == -1) {
				std::cerr << "Cannot open input file '" << in << "': "
					<< ::strerror(errno) << std::endl;
			}
		}
		else {
			fd_in = STDIN_FILENO;
		}

		if (!out.empty()) {
			fd_out = open(out.c_str(), O_WRONLY | O_TRUNC);
			if (fd_out == -1) {
				std::cerr << "Cannot open output file '" << out << "': "
						<< ::strerror(errno) << std::endl;
			}
		}
		else {
			fd_out = STDOUT_FILENO;
		}

		encode = false;
		pool.reset(new ThreadPool(nthreads));
		io_bufs.resize(pool->size());
	}

	virtual ~impl()
	{
		if (fd_in != -1) close(fd_in);
		if (fd_out != -1) close(fd_out);
	}

	bool readHeader()
	{
		auto hdr =  HPEncHeader::fromFd(fd_in, encode);

		if (!hdr) {
			throw std::runtime_error("No valid hpenc header found");
		}
		block_size = hdr->blen;
		auto alg = hdr->alg;

		// Setup cipher
		auto klen = AeadKeyLengths[static_cast<int>(alg)];
		auto key = kdf->genKey(klen);

		for (auto i = 0U; i < pool->size(); i ++) {
			auto cipher = std::make_shared<HPencAead>(alg);
			cipher->setKey(key);
			if (!nonce) {
				nonce.reset(new HPEncNonce(cipher->noncelen()));
			}
			ciphers.push_back(cipher);
			io_bufs[i] = std::make_shared<std::vector<byte> >();
			io_bufs[i]->resize(block_size + cipher->taglen());
		}

		return true;
	}

	bool writeBlock(ssize_t rd, std::vector<byte> *io_buf)
	{
		return util::atomicWrite(fd_out, io_buf->data(), rd) > 0;
	}

	ssize_t readBlock(size_t rd, std::vector<byte> *io_buf,
			const std::vector<byte> &n, std::shared_ptr<HPencAead> const &cipher)
	{
		if (rd > 0) {
			auto datalen = rd - cipher->taglen();
			MacTag tag;
			auto bs = htonl(datalen);

			if (rd < cipher->taglen()) {
				std::cerr << "Truncated input, cannot read MAC tag" << std::endl;
				return -1;
			}

			tag.data = io_buf->data() + datalen;
			tag.datalen = cipher->taglen();

			if (!cipher->decrypt(reinterpret_cast<byte *>(&bs), sizeof(bs),
					n.data(), n.size(), io_buf->data(), datalen,
					&tag, io_buf->data())) {
				std::cerr << "Verification failed" << std::endl;
				return -1;
			}

			return datalen;
		}

		return rd;
	}
};

HPEncDecrypt::HPEncDecrypt(std::unique_ptr<HPEncKDF> &&kdf,
		const std::string &in,
		const std::string &out,
		unsigned nthreads) :
	pimpl(new impl(std::move(kdf), in, out, nthreads))
{
}

HPEncDecrypt::~HPEncDecrypt()
{
}

void HPEncDecrypt::decrypt(bool encode) throw(std::runtime_error)
{
	pimpl->encode = encode;
	bool last = false;

	if (pimpl->readHeader()) {
		auto nblocks = 0U;
		for (;;) {
			auto blocks_read = 0;
			std::vector< std::future<ssize_t> > results;
			auto i = 0U;
			for (auto &buf : pimpl->io_bufs) {

				auto rd = util::atomicRead(pimpl->fd_in,
						buf->data(),
						pimpl->block_size + pimpl->ciphers[0]->taglen());
				if (rd > 0) {
					auto n = pimpl->nonce->incAndGet();
					results.emplace_back(
							pimpl->pool->enqueue(
									&impl::readBlock, pimpl.get(),
									rd, buf.get(), n,
									pimpl->ciphers[i]
							));
					blocks_read ++;
					if (rd < pimpl->block_size) {
						// Last block
						last = true;
						break;
					}
				}
				else {
					last = true;
					break;
				}
				i ++;
			}

			i = 0;
			for(auto && result: results) {
				result.wait();
				auto rd = result.get();
				if (rd < 0) {
					throw std::runtime_error("Cannot decrypt block");
				}
				if (rd > 0) {
					if (!pimpl->writeBlock(rd, pimpl->io_bufs[i].get())) {
						throw std::runtime_error("Write error");
					}
				}

				i ++;
			}
			if (last) {
				return;
			}
			if (++nblocks % rekey_blocks == 0) {
				// Rekey all cipers
				auto nkey = pimpl->kdf->genKey(pimpl->ciphers[0]->keylen());
				for (auto const &cipher : pimpl->ciphers) {
					cipher->setKey(nkey);
				}
			}
		}
	}
}

} /* namespace hpenc */
