# Use an official Golang runtime as a parent image
FROM golang:1.23.0
# Set the working directory to /go/src/app
WORKDIR /go/src/app

# Copy the code into the container
COPY . .

# Build the Go application
RUN go build -o app .

# Expose port 8080 for the API server
EXPOSE 8002

# Run the command to start the API server when the container starts
CMD ["/bin/sh", "./run.sh"]
