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
#ifndef ALIGNED_ALLOC_H_
#define ALIGNED_ALLOC_H_

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <limits>

template <typename T, std::size_t Alignment>
class aligned_allocator
{
public:
	typedef T * pointer;
	typedef const T * const_pointer;
	typedef T& reference;
	typedef const T& const_reference;
	typedef T value_type;
	typedef std::size_t size_type;
	typedef ptrdiff_t difference_type;

	T * address(T& r) const
	{
		return &r;
	}

	const T * address(const T& s) const
	{
		return &s;
	}

	std::size_t max_size() const
	{
		return std::numeric_limits<std::size_t>::max() / sizeof(T);
	}

	template <typename U>
	struct rebind
	{
		typedef aligned_allocator<U, Alignment> other;
	};

	bool operator!=(const aligned_allocator& other) const
	{
		return !(*this == other);
	}
	void construct(T * const p, const T& t) const
	{
		void * const pv = static_cast<void *>(p);
		new (pv) T(t);
	}
	void destroy(T * const p) const
	{
		p->~T();
	}
	bool operator==(const aligned_allocator& other) const
	{
		return true;
	}

	aligned_allocator() { }
	aligned_allocator(const aligned_allocator&) { }
	template <typename U> aligned_allocator(const aligned_allocator<U, Alignment>&) { }
	~aligned_allocator() { }


	T * allocate(const std::size_t n) const
	{
		if (n == 0) {
			return NULL;
		}

		if (n > max_size())
		{
			throw std::length_error("aligned_allocator<T>::allocate() - Integer overflow.");
		}

		void *pv;

		if (::posix_memalign(&pv, Alignment, n * sizeof(T)) != 0) {
			throw std::bad_alloc();
		}
		return static_cast<T *>(pv);
	}
	void deallocate(T * const p, const std::size_t n) const
	{
		free((void *)p);
	}
	template <typename U>
	T * allocate(const std::size_t n, const U * /* const hint */) const
	{
		return allocate(n);
	}
private:
	aligned_allocator& operator=(const aligned_allocator&);
};

#endif /* ALIGNED_ALLOC_H_ */
