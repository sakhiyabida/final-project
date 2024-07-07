# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements.txt file into the container
COPY requirements.txt ./

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . .

# Install additional tools and dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    unoconv \
    net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variables
ENV FLASK_APP=main.py
ENV FLASK_RUN_HOST=0.0.0.0

# Run flask when the container launches
CMD ["flask", "run"]



FROM python:3.9

# Install dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    metasploit-framework \
    net-tools \
    netifaces \
    pyfiglet

# Install Python dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application code
COPY . /app
WORKDIR /app

# Set the command to run the Flask app
CMD ["python", "main.py"]
