#!/usr/bin/env bash
# exit on error
set -o errexit

# Install system dependencies
apt-get update
apt-get install -y python3-dev libpq-dev

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run migrations
python manage.py collectstatic --no-input
python manage.py migrate
