#!/bin/bash

# Generate 32-byte encryption key
ENCRYPTION_KEY=$(openssl rand -base64 32)
echo "Generated ENCRYPTION_KEY: $ENCRYPTION_KEY"

# Generate JWT secret
JWT_SECRET=$(openssl rand -base64 64)
echo "Generated JWT_SECRET: $JWT_SECRET"

# Instructions for using the keys
echo -e "\nAdd these to your .env file:"
echo "ENCRYPTION_KEY=$ENCRYPTION_KEY"
echo "JWT_SECRET=$JWT_SECRET" 