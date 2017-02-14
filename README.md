# `hpenc` - fast encryption command line tool

## Use cases and features

If you do not want to read thousands of words of text here is a brief of features that `hpenc` provides:

- You want to transfer data between your servers quickly. That could be terabytes of data, but your NIC
is powerful and can transfer up to 10G. Your current options are:
	* `ssh` - a good choice, but not very fast and it cannot use more than 1 CPU
	* `gpg` - slow, old and requires complex keys generation
	* `openssl enc` - no integrity check, no multi-core support

For `hpenc` you can use **all** your CPU cores and burn your network as fast as possible. All data passed is
**authenticated** meaning that all corruption will be detected immediately. That is more like encryption +
digest, but much much faster. On the other hand, `hpenc` utilizes the modern cryptographic ciphers and tries
to use hardware acceleration if possible.

I understand that external dependencies might be evil for servers transferring, hence, `hpenc` depends only on `openssl` and `sodium` libraries and `C++11` compiler which is likely available in all operating system.

- You want to store like 5Tb of movies on some backup space available via `ftp`. You do not want anybody but you to watch those movies. `hpenc` allows you to encrypt and authenticate your backup quickly. Of course, you need some extra
space for storing authentication data but it is negligible in terms of the overall size (about 16K for each gigabyte of data). In this case you still do not need to create som complex atchitecture of keys: just generate a key and store it in some secure place.

- You need some fast entropy generator. Of course, you could use `rand()` function from your libc. However,
it is very insecure if you want cryptographic input. `hpenc` provides secure pseudo-random data on a
very high speed. In fact, you can generate up to 2 GB of random numbers per second on a modern hardware (Inter Core i7 SandyBridge)! Comparing to 14 Mb per second for reading from `/dev/urandom` it is really fast (but still secure).

If you are still not convinced here is a list of features provided by `hpenc`:

- **Authenticated encryption** - your data *cannot* be forged or corrupted without detection.
- **Parallel processing** - `hpenc` uses block IO and you can process multiple blocks simultaneously, which is extremely useful if you have multi-core environment.
- **Strong ciphers** - `hpenc` uses the state-of-art [`aes-gcm`](http://en.wikipedia.org/wiki/Galois/Counter_Mode) and [`chacha20`](http://cr.yp.to/chacha.html) ciphers in counter-like mode. This provides up to 2^248 complexity to break the cipher [1](http://eprint.iacr.org/2007/472.pdf) (2^128 complexity is considered as totally secure in pre-quantum-computer world).
- **Easy interface** - `hpenc < in > out`: what could be more simple?
- **Hardware acceleration** - do you have the modern CPU? `hpenc` can utilize all its advanced cryptography functions defined for `AES-NI` and `PCLMULQDQ` instructions (that must be supported by openssl). For those with old or embedded CPU (such as ARM), `hpenc` provides portable and fast `chacha20` cipher.
- **Simple key management** - all that you need to remember/transfer is 52 symbols shared key. All these symbols are *pronounceable* meaning that you can tell them using a phone or writing them down on a sheet of paper without worrying about `o` and `0` ambiguity.
- **(Almost) zero dependencies** - `hpenc` requires only `libcrypto` from openssl >= 1.0.1d and C++11 compatible compiler: gcc 4.7+ or clang 3.3+. If you use some punny system that does not satisfy these requirements, than you don't care about performance anyway.
- **Secure random numbers generator** - `hpenc` can work as pseudo-random numbers generator. In a set of standard tests (diehard) on the generated sequences `hpenc` generates *secure* sequences of pseudo-random numbers on a very high speed (gigabytes per second). 

## Examples of usage

Generate PSK:

    hpenc psk

Encrypt data:

    echo 'data' | hpenc -k 8jc38bntqehs31f3q8j4du4ry88k34ugh6eux6aoggpkbywgok9y > encrypted

Decrypt data:

    hpenc -k 8jc38bntqehs31f3q8j4du4ry88k34ugh6eux6aoggpkbywgok9y -d < encrypted

Run as random number generator:

    hpenc -r -b 1M -c 10 > random

Securely reset all data on your hard drive:

    hpenc -r -b 1M > /dev/hda

Move data over the network (using [bar](http://www.theiling.de/projects/bar.html) utility):

    bar -b 16M -s 102400M /dev/vg0/lvol1 | ./hpenc -b 16M -k 8jc38bntqehs31f3q8j4du4ry88k34ugh6eux6aoggpkbywgok9y | nc target 1234
    nc -l 1234 | ./hpenc -d -k 8jc38bntqehs31f3q8j4du4ry88k34ugh6eux6aoggpkbywgok9y > /dev/vg0/lvol


## Summary and motivation

`hpenc` provides command line API for authenticated encryption algorithms, in particular `AES-[128|256]-GCM` and
`ChaCha20-Poly1305`. This tool is intended to perform bulk encryption with authentication tags for further data
transfer. Unlike `openssl enc` this tool supports **only** modern authenticated encryption ciphers providing both
secrecy and integrity of input data.

`hpenc` does not perform any asymmetric key exchange but uses pre-shared keys instead. Therefore, a user can generate
`psk` on one machine:

~~~
hpenc -a chacha psk
Random key: en1o46877q7zxcen1cgbjc8qzjk1etdmsoctwyi3yy38ant7q59b
~~~

Then this key should be used for both encryption and decryption procedures, for example:

* encryption: 

~~~
hpenc -a chacha -k en1o46877q7zxcen1cgbjc8qzjk1etdmsoctwyi3yy38ant7q59b < in > out
~~~

* decryption:

~~~
hpenc -d -k en1o46877q7zxcen1cgbjc8qzjk1etdmsoctwyi3yy38ant7q59b < in > out
~~~

`hpenc` uses block mode of operations meaning that the input is divided into blocks of data.
By default, block's size is equal to `4096`, however, for large data portions it is advised to
increase it to several megabytes:

~~~
hpenc -a chacha -k en1o46877q7zxcen1cgbjc8qzjk1etdmsoctwyi3yy38ant7q59b -b 4M < in > out
~~~

The maximum size of a block is limited to 16 megabytes (because we need to change nonces).

## Performance results

Hardware used: Intel(R) Core(TM) i7-4770K CPU @ 3.50GHz (thanks to [openwall](http://openwall.com) for the hardware provided)

* Graph of dependency of encryption throughput on the input block size:

![graph](https://github.com/vstakhov/hpenc/raw/master/doc/hpenc_throughput_from_block_size.png "Throughput from block size")

* Graph of dependency of encryption throughput on the number of CPU cores:

![graph](https://github.com/vstakhov/hpenc/raw/master/doc/hpenc_throughput_from_cores_count.png "Throughput from cores count")

Hardware used: AMD Opteron(tm) Processor 6344, 24 physical cores, 48 logical cores, 4 NUMA nodes

* Graph of dependency of PRF throughput on the number of CPU cores:

![graph](https://github.com/vstakhov/hpenc/raw/master/doc/hpenc_prf_throughput_from_cores_count_amd_opteron.png "Throughput from cores count")


## Security model

`hpenc` uses stream ciphers with authentication tag:

* aes-[128|256]-gcm - high performance cipher that sometimes could be accelerated by the hardware using
`AES-NI` and `PCLMULQDQ` instructions in the modern processors (such as Intel Sandybridge or newer). These ciphers
are supported via `openssl` library (openssl must be >= 1.0.1)
* chacha20-poly1305 - high performance cipher that doesn't require any hardware acceleration. This cipher could be
significantly faster in case of generic hardware.

Internally, `hpenc` uses pre-shared key for key derivation only. For this purposes, it applies
`xchacha20` stream cipher to a string of all zeroes using this pre-shared key as key and monotonically
increasing counter as nonce, the inital nonce is encoded to the message's header and is chosen randomly.

During bulk encryption `hpenc` splits input into blocks of data. Each block is appended with MAC tag calculated
from the encrypted content and non-encrypted portion that represents the length of the current block. So far,
data content and length are both authenticated.

Each block is encrypted using monotonically increasing counter as nonce. This counter starts from `1` and can count up
to 2^64 (depending on ciphers) allowing thus up to 2^64 blocks being encrypted. However, `hpenc` also derives new key
each 4096 blocks removing this limitation as well.

`hpenc` append a small header to each stream encrypted which helps decrypter to figure out the following attributes:

1. magic of the stream and version (`'hpenc' \0 \0 \1`, 8 bytes)
2. algorithm code (network byte order, 4 bytes)
3. block length (network byte order, 4 bytes)
4. initial nonce/salt for deriving keys (24 bytes)

Therefore, the overall overhead of encryption is calculated as following:

~~~
(nblocks) * (mac_length) + 16
~~~

So far, for 1Gb stream and 1Mb block size it is `(16 * 1024 + 40)` ~= 16K 

## PRF security

~~~
$ ./src/hpenc -r | dieharder -g 200 -a

#=============================================================================#
#            dieharder version 3.31.1 Copyright 2003 Robert G. Brown          #
#=============================================================================#
   rng_name    |rands/second|   Seed   |
stdin_input_raw|  4.07e+07  |3553750306|
#=============================================================================#
        test_name   |ntup| tsamples |psamples|  p-value |Assessment
#=============================================================================#
   diehard_birthdays|   0|       100|     100|0.49770684|  PASSED  
      diehard_operm5|   0|   1000000|     100|0.35666073|  PASSED  
  diehard_rank_32x32|   0|     40000|     100|0.93096659|  PASSED  
    diehard_rank_6x8|   0|    100000|     100|0.71387575|  PASSED  
   diehard_bitstream|   0|   2097152|     100|0.94036648|  PASSED  
        diehard_opso|   0|   2097152|     100|0.35376777|  PASSED  
        diehard_oqso|   0|   2097152|     100|0.87245846|  PASSED  
         diehard_dna|   0|   2097152|     100|0.73729069|  PASSED  
diehard_count_1s_str|   0|    256000|     100|0.25678488|  PASSED  
diehard_count_1s_byt|   0|    256000|     100|0.03694089|  PASSED  
 diehard_parking_lot|   0|     12000|     100|0.96263190|  PASSED  
    diehard_2dsphere|   2|      8000|     100|0.97821441|  PASSED  
    diehard_3dsphere|   3|      4000|     100|0.97629855|  PASSED  
     diehard_squeeze|   0|    100000|     100|0.87578355|  PASSED  
        diehard_runs|   0|    100000|     100|0.06327493|  PASSED  
        diehard_runs|   0|    100000|     100|0.58609759|  PASSED  
       diehard_craps|   0|    200000|     100|0.26970372|  PASSED  
       diehard_craps|   0|    200000|     100|0.71135830|  PASSED
~~~

## Further tasks

1. ~~Multithreading (stream ciphers works perfectly fine for multiple threads)~~
2. PBKDF (for password based keys)
3. ???
4. Profit 
