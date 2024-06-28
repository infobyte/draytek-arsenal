
#!/bin/bash

# Check if the mounting path is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <mounting_path> <variable_arguments>"
    exit 1
fi

# Extract the mounting path
mounting_path="$1"

# Check if the mounting path exists
if [ ! -d "$mounting_path" ]; then
    echo "Mounting path '$mounting_path' does not exist."
    exit 1
fi

echo "Mounting path: $mounting_path"

# Check if Docker image 'mips-tools' exists
if ! docker image inspect mips-tools &> /dev/null; then
    echo "Docker image 'mips-tools' not found, building it in $(dirname "$0")"
    docker build -t mips-tools $(dirname "$0")
fi

shift 1

echo "Running $@"

# Run Docker container named 'mips-tools'
docker run -it -v "$mounting_path":/shared mips-tools "$@"
