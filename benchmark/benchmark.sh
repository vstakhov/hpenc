#!/bin/sh

HPENC=${HPENC:-"./src/hpenc"}
ALGORITHMS="aes-128 aes-256 chacha20 tiaoxin"
BLOCK_SIZES="4096 65536 524288 1048576 8388608 16777216"
DATA_SIZE="2147483648"

perl -ne_EXPR="{printf \"%d\t\", (${DATA_SIZE} / \$2) / (1024*1024)*8}"
PERL_EXPR="my @elts = split /\s+/; my \$res = (${DATA_SIZE} / (1.0 * \$elts[1])) / (1024*1024)*8; printf \"%.0f\t\", \$res;"

if [ "F$NCPU" = "F" ] ; then
	NCPU=`getconf _NPROCESSORS_ONLN 2>/dev/null`
	if [ $? -ne 0 ] ; then
		NCPU=`getconf NPROCESSORS_ONLN 2>/dev/null`
	fi
fi

# Block size tests
echo "Block size encrypt test (all cores). bytes : mbits/second"
printf "Block\tAES-128\tAES-256\tChacha\tTiaoxin\n"
for _b in $BLOCK_SIZES ; do
	printf "$_b\t"
	_cnt=$(($DATA_SIZE / $_b))
	for _a in $ALGORITHMS ; do
		/usr/bin/time -p $HPENC -b $_b -a $_a -c $_cnt < /dev/zero > /dev/null 2>/tmp/_hpenc_bench
		cat /tmp/_hpenc_bench | grep real | perl -ne "${PERL_EXPR}" || exit 1
		rm /tmp/_hpenc_bench
	done
	echo
done

# CPU count tests
echo "CPU cores encrypt test (16M block). core count : mbits/second"
printf "Cores\tAES-128\tAES-256\tChacha\tTiaoxin\n"
for _b in `seq $NCPU` ; do
	_cnt=$(($DATA_SIZE / 16777216))
	printf "$_b\t"
	for _a in $ALGORITHMS ; do
		/usr/bin/time -p $HPENC -b 16M -n $_b -a $_a -c $_cnt < /dev/zero > /dev/null 2>/tmp/_hpenc_bench
		cat /tmp/_hpenc_bench | grep real | perl -ne "${PERL_EXPR}" || exit 1
		rm /tmp/_hpenc_bench
	done
	echo
done

# PRF generator
echo "CPU cores PRF test (16M block). core count : mbits/second"
printf "Cores\tAES-128\tAES-256\tChacha\n"
for _b in `seq $NCPU` ; do
	_cnt=$(($DATA_SIZE / 16777216))
	printf "$_b\t"
	for _a in $ALGORITHMS ; do
		/usr/bin/time -p $HPENC -b 16M -n $_b -a $_a -c $_cnt -r > /dev/null 2>/tmp/_hpenc_bench
		cat /tmp/_hpenc_bench | grep real | perl -ne "${PERL_EXPR}" || exit 1
		rm /tmp/_hpenc_bench
	done
	echo
done
