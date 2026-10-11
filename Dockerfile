# Stage 1: Build from source using JDK 21
FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /build
COPY src/ ./src/
COPY data/ ./data/

# Compile all source files into classes
RUN mkdir -p out && \
    find src -name "*.java" > sources.txt && \
    javac --release 21 -encoding UTF-8 -d out @sources.txt

# Package into a standalone executable JAR
RUN jar cfe cipher-squad.jar App -C out .

# Stage 2: Runtime image
FROM eclipse-temurin:21-jre-alpine

ENV APP_HOME=/opt/ciphersquad
ENV CIPHER_SQUAD_DATA_DIR=/data

WORKDIR $APP_HOME

# Copy artifacts from builder
COPY --from=builder /build/cipher-squad.jar app.jar
COPY index.html ./index.html
COPY config/ ./config/
COPY data/ ./data/

# Create data directory for forensic persistence
RUN mkdir -p /data && chmod 755 /data

EXPOSE 8080

ENTRYPOINT ["java", "-Dcipher.squad.dataDir=/data", "-jar", "app.jar", "8080"]
