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
#include "encrypt.h"
#include "nonce.h"
#include "aead.h"
#include "util.h"
#include "kdf.h"
#include "thread_pool.h"

namespace hpenc
{

class HPEncEncrypt::impl {
public:
	std::unique_ptr<HPEncKDF> kdf;
	std::unique_ptr<HPencAead> cipher;
	std::unique_ptr<HPEncNonce> nonce;
	int fd_in, fd_out;
	unsigned block_size;
	std::vector<std::vector<byte> > io_bufs;
	HPEncHeader hdr;
	bool encode;
	std::unique_ptr<ThreadPool> pool;

	impl(std::unique_ptr<HPEncKDF> &&_kdf,
		const std::string &in,
		const std::string &out,
		AeadAlgorithm alg,
		unsigned _block_size,
		unsigned nthreads = 0) : kdf(std::move(_kdf)), block_size(_block_size),
			hdr(alg, _block_size)
	{
		cipher.reset(new HPencAead(alg));
		cipher->setKey(kdf->genKey(cipher->keylen()));
		nonce.reset(new HPEncNonce(cipher->noncelen()));
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
		for (auto i = 0U; i < pool->size(); i ++) {
			io_bufs[i].resize(block_size + cipher->taglen());
		}
	}

	virtual ~impl()
	{
		if (fd_in != -1) close(fd_in);
		if (fd_out != -1) close(fd_out);
	}

	bool writeHeader()
	{
		return hdr.toFd(fd_out, encode);
	}

	bool writeBlock(ssize_t rd, std::vector<byte> &io_buf,
			const std::vector<byte> &n)
	{
		if (rd > 0) {
			auto bs = htonl(rd);
			auto tag = cipher->encrypt(reinterpret_cast<byte *>(&bs), sizeof(bs),
					n.data(), n.size(), io_buf.data(), rd, io_buf.data());

			if (!tag) {
				return false;
			}

			auto mac_pos = io_buf.data() + rd;
			std::copy(tag->data, tag->data + tag->datalen, mac_pos);
			if (encode) {
				auto b64_out = util::base64Encode(io_buf.data(), rd + tag->datalen);
				if (::write(fd_out, b64_out.data(), b64_out.size()) == -1) {
					return false;
				}
			}
			else {
				if (::write(fd_out, io_buf.data(), rd + tag->datalen) == -1) {
					return false;
				}
			}
			return rd == block_size;
		}
		return false;
	}

	ssize_t readBlock(std::vector<byte> &io_buf)
	{
		return ::read(fd_in, io_buf.data(), block_size);
	}
};

HPEncEncrypt::HPEncEncrypt(std::unique_ptr<HPEncKDF> &&kdf,
		const std::string &in,
		const std::string &out,
		AeadAlgorithm alg,
		unsigned block_size) :
	pimpl(new impl(std::move(kdf), in, out, alg, block_size))
{
}

HPEncEncrypt::~HPEncEncrypt()
{
}

void HPEncEncrypt::encrypt(bool encode)
{
	pimpl->encode = encode;
	if (pimpl->writeHeader()) {
		auto nblocks = 0U;
		for (;;) {
			auto blocks_read = 0;
			std::vector< std::future<bool> > results;
			for (auto &buf : pimpl->io_bufs) {
				auto rd = pimpl->readBlock(buf);

				if (rd > 0) {
					auto n = pimpl->nonce->incAndGet();
					results.emplace_back(
							pimpl->pool->enqueue(
									&impl::writeBlock, pimpl.get(), rd, buf, n
							));
					blocks_read ++;
				}
			}

			for(auto && result: results) {
				result.wait();
				if (!result.get()) {
					throw std::runtime_error("Cannot encrypt block");
				}
			}


			if (++nblocks % rekey_blocks == 0) {
				pimpl->cipher->setKey(std::move(pimpl->kdf->genKey(
						pimpl->cipher->keylen())));
			}
		}
	}
}

} /* namespace hpenc */
