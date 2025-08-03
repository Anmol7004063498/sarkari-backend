# Start with a lightweight, official Python base image
FROM python:3.11-slim

# Set the working directory inside the container to /app
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Run the pip install command to install our libraries
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of our application code (main.py) into the container
COPY . .

# Tell Fleek that our application will be listening on port 8000
EXPOSE 8000

# The command to run when the container starts
CMD ["uvicorn", "main.py", "--host", "0.0.0.0", "--port", "8000"]