#!/bin/bash

NUMCORE=24

CMD=cmake-build-release/bin/benchmark/lib-benchmark_security
REPEAT=10

RESULTFOLDER=./result_security
FORMAT=csv

BENCHMARKS=("BFV")
LEVEL=("128" "192" "256")

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
	  for l in ${!LEVEL[@]};
	  do
	    level=${LEVEL[$l]}
		  benchmark=${BENCHMARKS[$j]}
		  $CMD$level --benchmark_repetitions=$REPEAT --benchmark_out=./$RESULTFOLDER/result_${benchmark}_${i}_${level}.$FORMAT --benchmark_out_format=$FORMAT --benchmark_filter=$benchmark
    done
	done
done
