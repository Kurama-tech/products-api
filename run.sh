#!/bin/bash

# Read the contents of the .env file into an array
IFS=$'\n' read -d '' -r -a envVars < .env

# Loop through the array and export each variable
for var in "${envVars[@]}"; do
  export "$var"
done

/app