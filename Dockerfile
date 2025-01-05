# Use an official OpenJDK runtime as the base image
FROM openjdk:17-jdk-slim

# Set the working directory in the container
WORKDIR /app

# Copy the packaged JAR file into the container
COPY target/commons-codec.jar app.jar

# Expose the port  of your application uses (if applicable)
# EXPOSE 8080 # Uncomment and adjust if your application listens on a specific port

# Set the command to run your application
CMD ["java", "-jar", "app.jar"]
