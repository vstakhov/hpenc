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
#include <arpa/inet.h>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include "util.h"
#include "aead.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <paths.h>
#include <signal.h>

static const char b32[]="ybndrfg8ejkmcpqxot1uwisza345h769";

using namespace hpenc;

std::string
hpenc::util::base32EncodeKey(const SessionKey *in)
{
	unsigned int i, x;
	auto input = in->data();
	auto len = in->size();

	int remain = -1;
	std::string result;

	result.reserve(len * 8 / 5 + 1);

	for (i = 0; i < len; i++) {
		switch (i % 5) {
		case 0:
			/* 8 bits of input and 3 to remain */
			x = input[i];
			remain = input[i] >> 5;
			result.push_back(b32[x & 0x1F]);
			break;
		case 1:
			/* 11 bits of input, 1 to remain */
			x = remain | input[i] << 3;
			result.push_back(b32[x & 0x1F]);
			result.push_back(b32[x >> 5 & 0x1F]);
			remain = x >> 10;
			break;
		case 2:
			/* 9 bits of input, 4 to remain */
			x = remain | input[i] << 1;
			result.push_back(b32[x & 0x1F]);
			remain = x >> 5;
			break;
		case 3:
			/* 12 bits of input, 2 to remain */
			x = remain | input[i] << 4;
			result.push_back(b32[x & 0x1F]);
			result.push_back(b32[x >> 5 & 0x1F]);
			remain = x >> 10 & 0x3;
			break;
		case 4:
			/* 10 bits of output, nothing to remain */
			x = remain | input[i] << 2;
			result.push_back(b32[x & 0x1F]);
			result.push_back(b32[x >> 5 & 0x1F]);
			remain = -1;
			break;
		default:
			/* Not to be happen */
			break;
		}

	}
	if (remain >= 0) {
		result.push_back(b32[remain]);
	}

	return result;
}

static byte const b32_dec[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x12, 0xff, 0x19, 0x1a, 0x1b, 0x1e, 0x1d,
	0x07, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x18, 0x01, 0x0c, 0x03, 0x08, 0x05, 0x06,
	0x1c, 0x15, 0x09, 0x0a, 0xff, 0x0b, 0x02, 0x10,
	0x0d, 0x0e, 0x04, 0x16, 0x11, 0x13, 0xff, 0x14,
	0x0f, 0x00, 0x17, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x18, 0x01, 0x0c, 0x03, 0x08, 0x05, 0x06,
	0x1c, 0x15, 0x09, 0x0a, 0xff, 0x0b, 0x02, 0x10,
	0x0d, 0x0e, 0x04, 0x16, 0x11, 0x13, 0xff, 0x14,
	0x0f, 0x00, 0x17, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

std::unique_ptr<SessionKey>
hpenc::util::base32DecodeKey(const std::string &in)
{
	auto res = util::make_unique<SessionKey>();
	auto acc = 0U;
	auto processed_bits = 0;

	res->reserve(in.size() * 8 / 5);

	for (const auto c : in) {
		if (processed_bits >= 8) {
			// Output one character
			processed_bits -= 8;
			res->push_back(acc & 0xFF);
			acc >>= 8;
		}
		// Least significant part
		auto decoded = b32_dec[static_cast<byte>(c)];
		if (decoded == 0xff) {
			// Invalid input
			throw std::runtime_error("Non-Valid base32!");
		}
		acc = (decoded << processed_bits) | acc;
		processed_bits += 5;
	}

	if (processed_bits > 0) {
		res->push_back(acc & 0xFF);
	}

	return res;
}

const static char padCharacter = '=';

std::vector<byte> hpenc::util::base64Decode(const std::string& input)
{
	if (input.length() % 4) //Sanity check
		throw std::runtime_error("Non-Valid base64!");

	size_t padding = 0;

	if (input.length())
	{
		if (input[input.length()-1] == padCharacter)
			padding++;
		if (input[input.length()-2] == padCharacter)
			padding++;
	}
	//Setup a vector to hold the result
	std::vector<byte> decodedBytes;
	decodedBytes.reserve(((input.length()/4)*3) - padding);

	auto temp = 0U;
	auto cursor = input.begin();

	while (cursor < input.end())
	{
		for (auto quantumPosition = 0U; quantumPosition < 4; quantumPosition++)
		{
			temp <<= 6;
			if       (*cursor >= 0x41 && *cursor <= 0x5A)
				temp |= *cursor - 0x41;
			else if  (*cursor >= 0x61 && *cursor <= 0x7A)
				temp |= *cursor - 0x47;
			else if  (*cursor >= 0x30 && *cursor <= 0x39)
				temp |= *cursor + 0x04;
			else if  (*cursor == 0x2B)
				temp |= 0x3E;
			else if  (*cursor == 0x2F)
				temp |= 0x3F;
			else if  (*cursor == padCharacter)
			{
				switch( input.end() - cursor )
				{
				case 1: //One pad character
					decodedBytes.push_back((temp >> 16) & 0x000000FF);
					decodedBytes.push_back((temp >> 8 ) & 0x000000FF);
					return decodedBytes;
				case 2: //Two pad characters
					decodedBytes.push_back((temp >> 10) & 0x000000FF);
					return decodedBytes;
				default:
					throw std::runtime_error("Invalid Padding in Base 64!");
				}
			}  else
				throw std::runtime_error("Non-Valid Character in Base 64!");
			cursor++;
		}
		decodedBytes.push_back((temp >> 16) & 0x000000FF);
		decodedBytes.push_back((temp >> 8 ) & 0x000000FF);
		decodedBytes.push_back((temp      ) & 0x000000FF);
	}

	return decodedBytes;
}

const static char encodeLookup[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string hpenc::util::base64Encode(const byte *input, size_t len)
{
	std::string encoded;

	encoded.reserve(((len/3) + (len % 3 > 0)) * 4);

	auto temp = 0U;

	auto cursor = input;
	for(size_t idx = 0; idx < len/3; idx++)
	{
		temp  = (*cursor++) << 16; //Convert to big endian
		temp += (*cursor++) << 8;
		temp += (*cursor++);
		encoded.append(1,encodeLookup[(temp & 0x00FC0000) >> 18]);
		encoded.append(1,encodeLookup[(temp & 0x0003F000) >> 12]);
		encoded.append(1,encodeLookup[(temp & 0x00000FC0) >> 6 ]);
		encoded.append(1,encodeLookup[(temp & 0x0000003F)      ]);
	}
	switch(len % 3)
	{
	case 1:
		temp  = (*cursor++) << 16; //Convert to big endian
		encoded.append(1,encodeLookup[(temp & 0x00FC0000) >> 18]);
		encoded.append(1,encodeLookup[(temp & 0x0003F000) >> 12]);
		encoded.append(2,padCharacter);
		break;
	case 2:
		temp  = (*cursor++) << 16; //Convert to big endian
		temp += (*cursor++) << 8;
		encoded.append(1,encodeLookup[(temp & 0x00FC0000) >> 18]);
		encoded.append(1,encodeLookup[(temp & 0x0003F000) >> 12]);
		encoded.append(1,encodeLookup[(temp & 0x00000FC0) >> 6 ]);
		encoded.append(1,padCharacter);
		break;
	}

	return encoded;
}

std::unique_ptr<SessionKey>
hpenc::util::genPSK(AeadAlgorithm alg)
{
	unsigned len = AeadKeyLengths[static_cast<int>(AeadAlgorithm::CHACHA20_POLY_1305)];

	auto res = util::make_unique<SessionKey>();
	res->resize(len);

	auto rnd = open(rndfile, O_RDONLY);

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

struct HeaderWire {
	char magic[8];
	uint32_t alg;
	uint32_t blocklen;
	byte nonce[24];
};

static const char header_magic[8] = { 'h', 'p', 'e', 'n', 'c', 0, 0, 1 };

bool hpenc::HPEncHeader::toFd(int fd, bool encode)
{
	HeaderWire hdr;

	if (fd == -1) {
		return false;
	}

	::memcpy(hdr.magic, header_magic, sizeof(hdr.magic));
	hdr.alg = htonl(static_cast<uint32_t>(alg));
	hdr.blocklen = htonl(blen);

	if (nonce.size() != sizeof(hdr.nonce)) {
		throw std::runtime_error("Wire nonce length is not equal to internal one");
	}
	std::copy(std::begin(nonce), std::end(nonce), hdr.nonce);

	if (encode) {
		auto out = util::base64Encode(reinterpret_cast<byte *>(&hdr), sizeof(hdr));
		return (::write(fd, out.data(), out.size()) == out.size());
	}
	return (::write(fd, &hdr, sizeof(hdr)) == sizeof(hdr));
}

std::unique_ptr<HPEncHeader> hpenc::HPEncHeader::fromFd(int fd, bool encode)
{
	HeaderWire in;

	if (fd == -1 || ::read(fd, &in, sizeof(in)) != sizeof(in)) {
		return nullptr;
	}

	if (::memcmp(in.magic, header_magic, sizeof(in.magic)) != 0) {
		return nullptr;
	}


	auto alg = static_cast<AeadAlgorithm>(ntohl(in.alg));
	auto blen = ntohl(in.blocklen);
	if (blen > max_block) {
		// Disallow too large blocks
		return nullptr;
	}

	auto res = util::make_unique<HPEncHeader>(alg, blen);

	res->nonce.resize(sizeof(in.nonce));
	std::copy(std::begin(in.nonce), std::end(in.nonce), std::begin(res->nonce));

	return std::move(res);
}

size_t
hpenc::util::atomicRead(int fd, byte *buf, size_t n)
{
	auto *s = buf;
	size_t pos = 0;
	ssize_t res;

	while (n > pos) {
		res = ::read(fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return 0;
		case 0:
			errno = EPIPE;
			return pos;
		default:
			pos += (u_int)res;
			break;
		}
	}
	return pos;
}

size_t
hpenc::util::atomicWrite(int fd, const byte *buf, size_t n)
{
	auto *s = buf;
	size_t pos = 0;
	ssize_t res;

	while (n > pos) {
		res = ::write(fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return 0;
		case 0:
			errno = EPIPE;
			return pos;
		default:
			pos += (u_int)res;
			break;
		}
	}
	return pos;
}

std::unique_ptr<std::vector<byte> >
hpenc::util::readPassphrase()
{
	struct sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	struct sigaction savetstp, savettin, savettou, savepipe;
	struct termios oterm;
	int input, output, i;
	char ch;
	std::unique_ptr<std::vector<byte> > res;
	static volatile sig_atomic_t saved_signo[NSIG];
	static const unsigned max_len = 4096;

restart:
	if ((input = output = open(_PATH_TTY, O_RDWR)) == -1) {
		errno = ENOTTY;
		return std::move(res);
	}

	(void)fcntl(input, F_SETFD, FD_CLOEXEC);

	/* Turn echo off */
	if (tcgetattr(input, &oterm) != 0) {
		errno = ENOTTY;
		return res;
	}

	auto term = oterm;
	term.c_lflag &= ~(ECHO | ECHONL);
	(void)tcsetattr(input, TCSAFLUSH, &term);
	(void)write(output, "Enter passphrase: ", sizeof ("Enter passphrase: ") - 1);
	/* Save the current sighandler */
	for (i = 0; i < NSIG; i++) {
		saved_signo[i] = 0;
	}
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = [](int s) {saved_signo[s] = 1;};

	(void)sigaction(SIGALRM, &sa, &savealrm);
	(void)sigaction(SIGHUP, &sa, &savehup);
	(void)sigaction(SIGINT, &sa, &saveint);
	(void)sigaction(SIGPIPE, &sa, &savepipe);
	(void)sigaction(SIGQUIT, &sa, &savequit);
	(void)sigaction(SIGTERM, &sa, &saveterm);
	(void)sigaction(SIGTSTP, &sa, &savetstp);
	(void)sigaction(SIGTTIN, &sa, &savettin);
	(void)sigaction(SIGTTOU, &sa, &savettou);

	/* Now read a passphrase */
	/* Avoid resize */
	res.reset(new std::vector<byte>());
	res->reserve(max_len);
	auto rd = 0U;
	while (read(input, &ch, 1) == 1 && ch != '\n' && ch != '\r' && rd < max_len) {
		res->push_back(ch);
		rd ++;
	}
	(void)write (output, "\n", 1);

	/* Restore terminal state */
	if (memcmp (&term, &oterm, sizeof (term)) != 0) {
		while (tcsetattr (input, TCSAFLUSH, &oterm) == -1 &&
			errno == EINTR && !saved_signo[SIGTTOU]) ;
	}

	/* Restore signal handlers */
	(void)sigaction(SIGALRM, &savealrm, NULL);
	(void)sigaction(SIGHUP, &savehup, NULL);
	(void)sigaction(SIGINT, &saveint, NULL);
	(void)sigaction(SIGQUIT, &savequit, NULL);
	(void)sigaction(SIGPIPE, &savepipe, NULL);
	(void)sigaction(SIGTERM, &saveterm, NULL);
	(void)sigaction(SIGTSTP, &savetstp, NULL);
	(void)sigaction(SIGTTIN, &savettin, NULL);
	(void)sigaction(SIGTTOU, &savettou, NULL);

	close(input);
	/* Send signals pending */
	for (i = 0; i < NSIG; i++) {
		if (saved_signo[i]) {
			kill(getpid (), i);
			switch (i) {
			case SIGTSTP:
			case SIGTTIN:
			case SIGTTOU:
				goto restart;
			}
		}
	}

	return res;
}
