#!/bin/bash

if [[ $# -ne 3 ]];then
  echo "Cannot process a request invalid number of parameter"
fi
input_c_file="$1"
path_to_qcc="$2"
include_path_arg="$3" #-I<include path>

echo "#include \"exclusion.h\"" >temp_file.c
cat "$input_c_file" >> temp_file.c

rm output_file.c
$path_to_qcc "$include_path_arg" -I./include/ -E  -v temp_file.c | grep -v "#" > output_file.c
sed -i 's/\b__asm\b//g' output_file.c
rm temp_file.c