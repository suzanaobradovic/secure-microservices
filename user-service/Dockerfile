FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY . .
RUN mvn -T1C -DskipTests -pl user-service -am package spring-boot:repackage

FROM eclipse-temurin:21-jre
WORKDIR /app

COPY --from=build /workspace/user-service/target/*-SNAPSHOT.jar /app/app.jar

COPY jwt-keys /opt/keys

ENV JWT_PRIVATE_KEY_PATH=/opt/keys/jwt-private.der \
    JWT_PUBLIC_KEY_PATH=/opt/keys/jwt-public.der

EXPOSE 8081
ENTRYPOINT ["sh","-c","java -jar /app/app.jar \
  --server.port=${PORT:-8081} \
  --app.jwt.private-key-path=${JWT_PRIVATE_KEY_PATH} \
  --app.jwt.public-key-path=${JWT_PUBLIC_KEY_PATH}"]