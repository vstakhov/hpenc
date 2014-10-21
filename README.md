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

I understand that external dependencies might be evil for servers transferring, hence, `hpenc` depends only on openssl library and `C++11` compiler which is likely available in all operating system.

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

Hardware used: Intel Xeon E3 (Sandy Bridge), 4 physical cores, 8 logical cores

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
$ dd if=/dev/zero bs=16M | ./src/hpenc -b 16M -r | dieharder -a

#=============================================================================#
#            dieharder version 3.31.1 Copyright 2003 Robert G. Brown          #
#=============================================================================#
   rng_name    |rands/second|   Seed   |
        mt19937|  1.19e+08  |3793781669|
#=============================================================================#
        test_name   |ntup| tsamples |psamples|  p-value |Assessment
#=============================================================================#
   diehard_birthdays|   0|       100|     100|0.62150802|  PASSED  
      diehard_operm5|   0|   1000000|     100|0.89918464|  PASSED  
  diehard_rank_32x32|   0|     40000|     100|0.95500329|  PASSED  
    diehard_rank_6x8|   0|    100000|     100|0.46736764|  PASSED  
   diehard_bitstream|   0|   2097152|     100|0.53369612|  PASSED  
        diehard_opso|   0|   2097152|     100|0.95213609|  PASSED  
        diehard_oqso|   0|   2097152|     100|0.43272869|  PASSED  
         diehard_dna|   0|   2097152|     100|0.17455486|  PASSED  
diehard_count_1s_str|   0|    256000|     100|0.29399547|  PASSED  
diehard_count_1s_byt|   0|    256000|     100|0.64705391|  PASSED  
 diehard_parking_lot|   0|     12000|     100|0.86481685|  PASSED  
    diehard_2dsphere|   2|      8000|     100|0.29844138|  PASSED  
    diehard_3dsphere|   3|      4000|     100|0.67263770|  PASSED  
     diehard_squeeze|   0|    100000|     100|0.43511220|  PASSED  
        diehard_sums|   0|       100|     100|0.50062037|  PASSED  
        diehard_runs|   0|    100000|     100|0.57368121|  PASSED  
        diehard_runs|   0|    100000|     100|0.92388595|  PASSED  
       diehard_craps|   0|    200000|     100|0.62542645|  PASSED  
       diehard_craps|   0|    200000|     100|0.69873747|  PASSED  
 marsaglia_tsang_gcd|   0|  10000000|     100|0.21515618|  PASSED  
 marsaglia_tsang_gcd|   0|  10000000|     100|0.09530063|  PASSED  
         sts_monobit|   1|    100000|     100|0.40245407|  PASSED  
            sts_runs|   2|    100000|     100|0.81311232|  PASSED  
          sts_serial|   1|    100000|     100|0.60175686|  PASSED  
          sts_serial|   2|    100000|     100|0.71216220|  PASSED  
          sts_serial|   3|    100000|     100|0.16377217|  PASSED  
          sts_serial|   3|    100000|     100|0.99991264|   WEAK   
          sts_serial|   4|    100000|     100|0.04393005|  PASSED  
          sts_serial|   4|    100000|     100|0.00632723|  PASSED  
          sts_serial|   5|    100000|     100|0.03351511|  PASSED  
          sts_serial|   5|    100000|     100|0.34816375|  PASSED  
          sts_serial|   6|    100000|     100|0.08475886|  PASSED  
          sts_serial|   6|    100000|     100|0.80160922|  PASSED  
          sts_serial|   7|    100000|     100|0.45106065|  PASSED  
          sts_serial|   7|    100000|     100|0.78494757|  PASSED  
          sts_serial|   8|    100000|     100|0.39807272|  PASSED  
          sts_serial|   8|    100000|     100|0.27461777|  PASSED  
          sts_serial|   9|    100000|     100|0.39793620|  PASSED  
          sts_serial|   9|    100000|     100|0.86710900|  PASSED  
          sts_serial|  10|    100000|     100|0.90839617|  PASSED  
          sts_serial|  10|    100000|     100|0.73368190|  PASSED  
          sts_serial|  11|    100000|     100|0.89080387|  PASSED  
          sts_serial|  11|    100000|     100|0.47087799|  PASSED  
          sts_serial|  12|    100000|     100|0.21519430|  PASSED  
          sts_serial|  12|    100000|     100|0.42348828|  PASSED  
          sts_serial|  13|    100000|     100|0.18209807|  PASSED  
          sts_serial|  13|    100000|     100|0.50113305|  PASSED  
          sts_serial|  14|    100000|     100|0.95254299|  PASSED  
          sts_serial|  14|    100000|     100|0.55365219|  PASSED  
          sts_serial|  15|    100000|     100|0.52425160|  PASSED  
          sts_serial|  15|    100000|     100|0.57486420|  PASSED  
          sts_serial|  16|    100000|     100|0.09487942|  PASSED  
          sts_serial|  16|    100000|     100|0.04580379|  PASSED  
         rgb_bitdist|   1|    100000|     100|0.73859101|  PASSED  
         rgb_bitdist|   2|    100000|     100|0.93312022|  PASSED  
         rgb_bitdist|   3|    100000|     100|0.95216991|  PASSED  
         rgb_bitdist|   4|    100000|     100|0.39244818|  PASSED  
         rgb_bitdist|   5|    100000|     100|0.76644546|  PASSED  
         rgb_bitdist|   6|    100000|     100|0.40551409|  PASSED  
         rgb_bitdist|   7|    100000|     100|0.60905352|  PASSED  
         rgb_bitdist|   8|    100000|     100|0.30621151|  PASSED  
         rgb_bitdist|   9|    100000|     100|0.56997057|  PASSED  
         rgb_bitdist|  10|    100000|     100|0.07140820|  PASSED  
         rgb_bitdist|  11|    100000|     100|0.97178699|  PASSED  
         rgb_bitdist|  12|    100000|     100|0.33733827|  PASSED  
rgb_minimum_distance|   2|     10000|    1000|0.31411635|  PASSED  
rgb_minimum_distance|   3|     10000|    1000|0.37622029|  PASSED  
rgb_minimum_distance|   4|     10000|    1000|0.50792352|  PASSED  
rgb_minimum_distance|   5|     10000|    1000|0.88668160|  PASSED  
    rgb_permutations|   2|    100000|     100|0.08309492|  PASSED  
    rgb_permutations|   3|    100000|     100|0.43118579|  PASSED  
    rgb_permutations|   4|    100000|     100|0.19020352|  PASSED  
    rgb_permutations|   5|    100000|     100|0.70632932|  PASSED  
      rgb_lagged_sum|   0|   1000000|     100|0.43964494|  PASSED  
      rgb_lagged_sum|   1|   1000000|     100|0.55499796|  PASSED  
      rgb_lagged_sum|   2|   1000000|     100|0.79439758|  PASSED  
      rgb_lagged_sum|   3|   1000000|     100|0.60506193|  PASSED  
      rgb_lagged_sum|   4|   1000000|     100|0.51574090|  PASSED  
      rgb_lagged_sum|   5|   1000000|     100|0.35692196|  PASSED  
      rgb_lagged_sum|   6|   1000000|     100|0.09082710|  PASSED  
      rgb_lagged_sum|   7|   1000000|     100|0.86795428|  PASSED  
      rgb_lagged_sum|   8|   1000000|     100|0.96909312|  PASSED  
      rgb_lagged_sum|   9|   1000000|     100|0.43913478|  PASSED  
      rgb_lagged_sum|  10|   1000000|     100|0.73968586|  PASSED  
      rgb_lagged_sum|  11|   1000000|     100|0.24400434|  PASSED  
      rgb_lagged_sum|  12|   1000000|     100|0.03592821|  PASSED  
      rgb_lagged_sum|  13|   1000000|     100|0.97572585|  PASSED  
      rgb_lagged_sum|  14|   1000000|     100|0.23406462|  PASSED  
      rgb_lagged_sum|  15|   1000000|     100|0.57486365|  PASSED  
      rgb_lagged_sum|  16|   1000000|     100|0.72902474|  PASSED  
      rgb_lagged_sum|  17|   1000000|     100|0.82262372|  PASSED  
      rgb_lagged_sum|  18|   1000000|     100|0.23634573|  PASSED  
      rgb_lagged_sum|  19|   1000000|     100|0.70852283|  PASSED  
      rgb_lagged_sum|  20|   1000000|     100|0.99392448|  PASSED  
      rgb_lagged_sum|  21|   1000000|     100|0.25060411|  PASSED  
      rgb_lagged_sum|  22|   1000000|     100|0.66412800|  PASSED  
      rgb_lagged_sum|  23|   1000000|     100|0.30382070|  PASSED  
      rgb_lagged_sum|  24|   1000000|     100|0.97649082|  PASSED  
      rgb_lagged_sum|  25|   1000000|     100|0.96918785|  PASSED  
      rgb_lagged_sum|  26|   1000000|     100|0.97222525|  PASSED  
      rgb_lagged_sum|  27|   1000000|     100|0.95386866|  PASSED  
      rgb_lagged_sum|  28|   1000000|     100|0.05692469|  PASSED  
      rgb_lagged_sum|  29|   1000000|     100|0.88639885|  PASSED  
      rgb_lagged_sum|  30|   1000000|     100|0.29062391|  PASSED  
      rgb_lagged_sum|  31|   1000000|     100|0.34169804|  PASSED  
      rgb_lagged_sum|  32|   1000000|     100|0.57681173|  PASSED  
     rgb_kstest_test|   0|     10000|    1000|0.52369305|  PASSED  
     dab_bytedistrib|   0|  51200000|       1|0.46215754|  PASSED  
             dab_dct| 256|     50000|       1|0.29961442|  PASSED  
Preparing to run test 207.  ntuple = 0
        dab_filltree|  32|  15000000|       1|0.27828506|  PASSED  
        dab_filltree|  32|  15000000|       1|0.31976647|  PASSED  
Preparing to run test 208.  ntuple = 0
       dab_filltree2|   0|   5000000|       1|0.53657964|  PASSED  
       dab_filltree2|   1|   5000000|       1|0.68597829|  PASSED  
Preparing to run test 209.  ntuple = 0
        dab_monobit2|  12|  65000000|       1|0.40046124|  PASSED 
~~~

## Further tasks

1. ~~Multithreading (stream ciphers works perfectly fine for multiple threads)~~
2. PBKDF (for password based keys)
3. ???
4. Profit 