# hpenc - authenticated encryption command line tool

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

## Security model

`hpenc` uses stream ciphers with authentication tag:

* aes-[128|256]-gcm - high performance cipher that sometimes could be accelerated by the hardware using
`AES-NI` and `PCLMULQDQ` instructions in the modern processors (such as Intel Sandybridge or newer). These ciphers
are supported via `openssl` library (openssl must be >= 1.0.1)
* chacha20-poly1305 - high performance cipher that doesn't require any hardware acceleration. This cipher could be
significantly faster in case of generic hardware.

Internally, `hpenc` uses pre-shared key for key derivation only. For this purposes, it applies
`chacha20` stream cipher to a string of all zeroes using this pre-shared key as key and monotonically
increasing counter as nonce. This allows up to 2^64 unique session keys that are used for bulk encryption.

During bulk encryption `hpenc` splits input into blocks of data. Each block is appended with MAC tag calculated
from the encrypted content and non-encrypted portion that represents the length of the current block. So far,
data content and length are both authenticated.

Each block is encrypted using monotonically increasing counter as nonce. This counter starts from `1` and can count up
to 2^64 (depending on ciphers) allowing thus up to 2^64 blocks being encrypted. However, `hpenc` also derives new key
each 1024 blocks removing this limitation as well.

`hpenc` append a small header to each stream encrypted which helps decrypter to figure out the following attributes:

1. magic of the stream (`'hpenc' \0 \0 \0`, 8 bytes)
2. algorithm code (network byte order, 4 bytes)
3. block length (network byte order, 4 bytes)

Therefore, the overall overhead of encryption is calculated as following:

~~~
(nblocks) * (mac_length) + 16
~~~

So far, for 1Gb stream and 1Mb block size it is `(16 * 1024 + 16)` ~= 16K 

## Further tasks

1. Multithreading (stream ciphers works perfectly fine for multiple threads)
2. PBKDF (for password based keys)
3. ???
4. Profit 