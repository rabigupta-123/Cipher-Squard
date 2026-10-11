FROM eclipse-temurin:17-jre-alpine

# Set environment variables
ENV APP_HOME=/opt/sentryai
ENV CIPHER_SQUAD_DATA_DIR=/data

# Create app directory
WORKDIR $APP_HOME

# Copy the compiled jar and assets
# Assuming the build process produces a jar named sentryai.jar
COPY build/libs/sentryai.jar app.jar
COPY frontend/ /opt/sentryai/frontend/

# Create data directory for forensic persistence
RUN mkdir -p /data && chmod 755 /data

# Expose the default port
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
