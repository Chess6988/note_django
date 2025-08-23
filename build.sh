#!/usr/bin/env bash
# exit on error
set -o errexit

# Install system dependencies
apt-get update && apt-get install -y \
    python3-dev \
    libpq-dev \
    gcc \
    postgresql \
    postgresql-contrib

# Upgrade pip and install psycopg2 first
pip install --upgrade pip
pip install psycopg2-binary==2.9.9

# Then install other requirements
pip install -r requirements.txt

# Clear pyc files
find . -type f -name "*.pyc" -delete
find . -type d -name "__pycache__" -delete

# Run migrations
python manage.py collectstatic --no-input
python manage.py migrate
