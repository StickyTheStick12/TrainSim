#!/bin/bash

parentdir=$(dirname $(pwd))
target_dir="simulation/scripts"
python_files_directory="$parentdir/$target_dir"

# Specify the target file
target_file="switch.py"

# Use sed to replace port numbers from 5002 to 12345 and 5010 to 12344 in the target file
sed -i 's/\b5002\b/12345/g' "$python_files_directory/$target_file"
sed -i 's/\b5010\b/12344/g' "$python_files_directory/$target_file"
