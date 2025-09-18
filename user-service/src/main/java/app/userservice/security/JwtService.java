package app.userservice.security;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
@Slf4j
public class JwtService {
  private final RSAPrivateKey privateKey;
  private final String issuer;
  private final long expiresIn;

  public JwtService(
      @Value("${app.jwt.private-key-path}") String privateKeyPath,
      @Value("${app.jwt.issuer}") String issuer,
      @Value("${app.jwt.expires-in-seconds}") long expiresIn)
      throws Exception {
    byte[] pkcs8 = Files.readAllBytes(Path.of(privateKeyPath));
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
    this.privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
    this.issuer = issuer;
    this.expiresIn = expiresIn;
    log.info("Initialized JwtService with issuer: {}, token expiration (seconds): {}", issuer, expiresIn);
  }

  public String createToken(String subject, List<String> roles) throws Exception {
    log.info("Creating JWT token for subject: {}", subject);
    Instant now = Instant.now();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject(subject)
            .issuer(issuer)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(expiresIn)))
            .claim("roles", roles)
            .claim("authorities", roles)
            .jwtID(UUID.randomUUID().toString())
            .build();
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
    SignedJWT jwt = new SignedJWT(header, claims);
    jwt.sign(new RSASSASigner(privateKey));
    return jwt.serialize();
  }
}
