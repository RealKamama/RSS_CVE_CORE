# Use an official lightweight Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the file with Python dependencies
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# --no-cache-dir ensures that we don't store the package index, making the image smaller
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container at /app
COPY *.py .

# Expose port 5000 to allow communication to/from the Flask application
EXPOSE 5000

# Command to run the application when the container launches
# Gunicorn is a production-ready WSGI server. Using it is better practice than Flask's built-in server.
CMD ["gunicorn", "--workers", "3", "--bind", "0.0.0.0:5000", "app:app"]