#!/bin/bash

# Grant full read, write, and execute permissions to all files and directories in the workspace
sudo chmod  777 /opt/joern/joern-cli/workspace/*

# Get the list of directories to delete (excluding the most recently modified one)
find /opt/joern/joern-cli/workspace/* -maxdepth 0 -type d -printf '%T@ %p\n' | sort -n | head -n -1 | cut -d' ' -f2 > dirs_to_delete.txt

# Use xargs to delete the directories listed in dirs_to_delete.txt
cat dirs_to_delete.txt | xargs -I {} rm -r "{}"
