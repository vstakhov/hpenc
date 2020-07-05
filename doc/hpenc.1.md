% HPENC(1) User Commands

# NAME

hpenc - high performance encryption command line utility

# SYNOPSIS

hpenc [*options*] < input > output

hpenc [*options*] -r > output

hpenc psk

hpenc -h

# DESCRIPTION

`hpenc` provides command line API for authenticated encryption algorithms, in particular `AES-[128|256]-GCM` and
`ChaCha20-Poly1305`. This tool is intended to perform bulk encryption with authentication tags for further data
transfer. Unlike `openssl enc` this tool supports only modern authenticated encryption ciphers providing both
secrecy and integrity of input data.

`hpenc` utility reads input data from standard input and outputs encrypted (or decrypted data) to standard output.

To generate PSK one can use the following syntax:
	
	hpenc psk

For pseudo-random generator the following invocation could be used:

	hpenc -r

# OPTIONS

-a *algorithm*
:   Specify algorithm to use: `aes-128`, `aes-256` or `chacha20`

-d
:	Decrypt data instead of encryption. PSK must be specified for decryption in a command line

-r
:	Run in pseudo-random generator mode with no input needed

-b *block_size*
:	Use the specified block size instead of the default one (4KB). Use 'k' for kilobytes, 'm' for megabytes. Maximum block size is 16MB

-c *count*
:	Stop after processing *count* of blocks. Use 'k' for kiloblocks, 'm' for megablocks and 'g' for gigablocks

-k *key*
:	Use the specified *key* for encryption/decryption. Key is required for decryption and optional for encryption. The size of PSK is 52 base32 encoded symbols.

-K *env_var*
:	Read key for encryption/decryption from the specified *environment variable*. Key is required for decryption and optional for encryption. The size of PSK is 52 base32 encoded symbols.

-B
:	Encode output or input to base64

# RETURN VALUE

On exit `hpenc` returns `0` if operation was successfull and an error code otherwise.

# EXAMPLES

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

Move data over the network:
	
	bar -b 16M -s 102400M /dev/vg0/lvol1 | ./hpenc -b 16M -k 8jc38bntqehs31f3q8j4du4ry88k34ugh6eux6aoggpkbywgok9y | nc target 1234
	nc -l 1234 | ./hpenc -d -k 8jc38bntqehs31f3q8j4du4ry88k34ugh6eux6aoggpkbywgok9y > /dev/vg0/lvol

# SEE ALSO
Hpenc documentation and source codes may be downloaded from
<https://github.com/vstakhov/hpenc>.
