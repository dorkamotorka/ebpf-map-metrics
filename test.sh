#!/bin/bash

# Function to perform the update and delete operations
update_and_delete() {
    local map_id=$1
    
    # Perform the update operation 100 times
    for ((i=0; i<100; i++)); do
        sudo bpftool map update id $map_id key 0 0 0 0 value 1 0 0 0
    done

    # Perform the delete operation 50 times
    for ((i=0; i<50; i++)); do
        sudo bpftool map delete id $map_id key 0 0 0 0
    done
}

# Read map IDs from input
read -p "Enter the first map ID: " map_id1
read -p "Enter the second map ID: " map_id2
read -p "Enter the third map ID: " map_id3

# Perform operations on each map
update_and_delete $map_id1
update_and_delete $map_id2
update_and_delete $map_id3

echo "Operations completed on all maps."

