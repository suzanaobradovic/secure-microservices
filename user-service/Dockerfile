# ---- Build ----
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY . .
RUN mvn -T1C -DskipTests -pl user-service -am package

# ---- Run ----
FROM eclipse-temurin:21-jre
WORKDIR /app

COPY --from=build /workspace/user-service/target/user-service-*.jar /app/app.jar

COPY jwt-keys /opt/keys

ENV SERVER_PORT=8081 \
    JWT_PRIVATE_KEY_PATH=/opt/keys/jwt-private.der \
    JWT_PUBLIC_KEY_PATH=/opt/keys/jwt-public.der \
    JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseStringDeduplication"

EXPOSE 8081

ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar /app/app.jar"]