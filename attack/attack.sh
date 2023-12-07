#!/bin/bash

# Specify the directory where your Python files are located
python_files_directory="/path/to/your/python/files"

# Specify the target file
target_file="switch.py"

# Use sed to replace port numbers from 12345 to 5002 and 12344 to 5010 in the target file
sed -i 's/\b12345\b/5002/g' "$python_files_directory/$target_file"
sed -i 's/\b12344\b/5010/g' "$python_files_directory/$target_file"
