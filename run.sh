#!/bin/bash

# Start the two programs at the same time.
execute_at=`date --date "now+1min" +"%H:%M"`

echo "./memwars_axxxxxxxx" | at $execute_at
echo "./memwars_ayyyyyyyy" | at $execute_at
