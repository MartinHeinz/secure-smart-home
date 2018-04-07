#!/bin/bash
echo "Testing lambda"
./secure_smart_home/Scripts/activate.bat
python-lambda-local -l $1 -f $2 -t $3 $4 $5