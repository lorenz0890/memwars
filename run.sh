#!/bin/bash

execute_at=`date --date "now+1min" +"%H:%M"`

for i in {1..500}
do
  echo "./memwars_test $i" | at $execute_at
done