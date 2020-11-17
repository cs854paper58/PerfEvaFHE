#!/bin/bash

NUMCORE=2

CMD=cmake-build-release/bin/benchmark/lib-benchmark
REPEAT=2

RESULTFOLDER=./result
FORMAT=csv

BENCHMARKS=("BFVrns_KeyGen" "BFVrns_MultKeyGen" 
	"BFVrns_EvalAtIndexKeyGen" "BFVrns_Encryption" "BFVrns_Decryption" "BFVrns_Add" "BFVrns_MultNoRelin" "BFVrns_MultRelin" "BFVrns_EvalAtIndex" \
	"CKKS_KeyGen" "CKKS_MultKeyGen" "CKKS_EvalAtIndexKeyGen" "CKKS_Encryption" "CKKS_Decryption" "CKKS_Add" "CKKS_MultNoRelin" "CKKS_MultRelin" \
	"CKKS_EvalAtIndex" "BGVrns_KeyGen" "BGVrns_MultKeyGen" "BGVrns_EvalAtIndexKeyGen" "BGVrns_Encryption" "BGVrns_Decryption" "BGVrns_Add" \
	"BGVrns_MultNoRelin" "BGVrns_MultRelin" "BGVrns_EvalAtIndex" )

if [ -d "$RESULTFOLDER" ]; then
    echo "File exists"
    exit -1
else 
    mkdir $RESULTFOLDER
fi 

for ((i=1; i<=$NUMCORE; i++))
do 
	export OMP_NUM_THREADS=$i
	echo "the number of cores = $OMP_NUM_THREADS"
	for j in ${!BENCHMARKS[@]};
	do
		benchmark=${BENCHMARKS[$j]}
		$CMD --benchmark_repetitions=$REPEAT --benchmark_out=./$RESULTFOLDER/result_${benchmark}_$NUMCORE.$FORMAT --benchmark_out_format=$FORMAT --benchmark_filter=$benchmark
	done
done
