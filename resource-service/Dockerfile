# ---- Build ----
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY . .
RUN mvn -T1C -DskipTests -pl resource-service -am package

# ---- Run ----
FROM eclipse-temurin:21-jre
WORKDIR /app

COPY --from=build /workspace/resource-service/target/resource-service-*.jar /app/app.jar

COPY jwt-keys /opt/keys

ENV SERVER_PORT=8082 \
    JWT_PUBLIC_KEY_PATH=/opt/keys/jwt-public.der \
    JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseStringDeduplication"

EXPOSE 8082

ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar /app/app.jar"]