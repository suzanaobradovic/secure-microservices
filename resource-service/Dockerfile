FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY . .
RUN mvn -T1C -DskipTests -pl resource-service -am package spring-boot:repackage

FROM eclipse-temurin:21-jre
WORKDIR /app

COPY --from=build /workspace/resource-service/target/*-SNAPSHOT.jar /app/app.jar

COPY jwt-keys /opt/keys
ENV JWT_PUBLIC_KEY_PATH=/opt/keys/jwt-public.der

EXPOSE 8082
ENTRYPOINT ["sh","-c","java -jar /app/app.jar \
  --server.port=${PORT:-8082} \
  --app.jwt.public-key-path=${JWT_PUBLIC_KEY_PATH}"]