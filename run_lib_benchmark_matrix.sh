#!/bin/bash

NUMCORE=24

CMD=build/bin/benchmark/lib-benchmark_matrix
REPEAT=10

RESULTFOLDER=./result_matrix
FORMAT=csv

#BENCHMARKS=("BFV")
#LEVEL=("128" "192" "256")

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
#	for j in ${!BENCHMARKS[@]};
#	do
#	  for l in ${!LEVEL[@]};
#	  do
#	    level=${LEVEL[$l]}
#		  benchmark=${BENCHMARKS[$j]}
		  $CMD --benchmark_repetitions=$REPEAT --benchmark_out=./$RESULTFOLDER/result_${i}.$FORMAT --benchmark_out_format=$FORMAT
#    done
#	done
done
