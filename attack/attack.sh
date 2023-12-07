#!/bin/bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define the target directory relative to the script
target_dir="simulation/scripts"

# Construct the absolute path to the target directory (/a/b/scripts)
absolute_path="$script_dir/$target_dir"

# Specify the target file
target_file="switch.py"

# Use sed to replace port numbers from 12345 to 5002 and 12344 to 5010 in the target file
sed -i 's/\b12345\b/5002/g' "$absolute_path/$target_file"
sed -i 's/\b12344\b/5010/g' "$absolute_path/$target_file"
