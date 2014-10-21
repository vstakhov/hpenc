#!/bin/sh

HPENC=${HPENC:-"./src/hpenc"}
ALGORITHMS="aes-128 aes-256 chacha20"
BLOCK_SIZES="4096 65536 524288 1048576 8388608 16777216"
DATA_SIZE="2147483648"

if [ "F$NCPU" = "F" ] ; then
	NCPU=`getconf _NPROCESSORS_ONLN 2>/dev/null`
	if [ $? -ne 0 ] ; then
		NCPU=`getconf NPROCESSORS_ONLN 2>/dev/null`
	fi
fi

# Block size tests
echo "Block size tests (all cores)"
for _b in $BLOCK_SIZES ; do
	printf "$_b\t"
	_cnt=$(($DATA_SIZE / $_b))
	for _a in $ALGORITHMS ; do
		/usr/bin/time -p -o /tmp/_hpenc_bench $HPENC -b $_b -a $_a -c $_cnt < /dev/zero > /dev/null 2>&1 
		cat /tmp/_hpenc_bench | grep real | awk '{printf "%s\t", $2}'
		rm /tmp/_hpenc_bench
	done
	echo
done

# CPU count tests
echo "CPU cores tests (16M block)"
for _b in `seq $NCPU` ; do
	_cnt=$(($DATA_SIZE / 16777216))
	printf "$_b\t"
	for _a in $ALGORITHMS ; do
		/usr/bin/time -p -o /tmp/_hpenc_bench $HPENC -b 16M -n $_b -a $_a -c $_cnt < /dev/zero > /dev/null 2>&1
		cat /tmp/_hpenc_bench | grep real | awk '{printf "%s\t", $2}'
		rm /tmp/_hpenc_bench
	done
	echo
done
