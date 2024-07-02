
#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <command> [arguments...]" >&2
    exit 1
fi

# Determine which command to execute
case "$1" in
    "compile")
        # Check if the correct number of arguments is provided for compile
        if [ "$#" -lt 3 ]; then
            echo "Usage: $0 compile <output_file> <input_file1> [<input_file2> ...]" >&2
            exit 1
        fi
        # Extract output file path
        output_file="/shared/$2"
        # Shift arguments to get input files
        shift 2
        input_files=()
        for file in "$@"; do
            input_files+=("/shared/$file")
        done
        # Execute the compile command
        echo "Compiling ${input_files[*]} to $output_file..."

        mips-linux-gnu-gcc -nostdlib -r -mno-abicalls -ffreestanding -msoft-float \
                -o $output_file ${input_files[*]}
        ;;
    "merge")
        # Check if the correct number of arguments is provided for merge
        if [ "$#" -ne 4 ]; then
            echo "Usage: $0 merge <file1> <file2> <output_file>" >&2
            exit 1
        fi
        # Execute the merge command
        echo "Merging $2 and $3 to $4..."

        mips-linux-gnu-ld -relocatable "/shared/$2" "/shared/$3" -o "/shared/$4"
        ;;
    "shell")
        # Execute the shell command
        echo "Entering interactive shell..."
        # Actual shell command goes here
        bash
        ;;
    "run")
        # Check if the correct number of arguments is provided for run
        if [ "$#" -lt 2 ]; then
            echo "Usage: $0 run <executable> [<arguments> ...]" >&2
            exit 1
        fi
        # Extract executable
        executable="$2"
        # Shift arguments to get the arguments for the executable
        shift 2
        # Execute the run command
        bash -c "$executable $@"
        # bash -c "$executable $@"
        # Actual run command goes here
        ;;
    *)
        # Invalid command
        echo "Unknown command: $1" >&2
        exit 1
        ;;
esac
