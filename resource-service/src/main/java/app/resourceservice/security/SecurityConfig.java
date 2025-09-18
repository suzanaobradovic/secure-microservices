package app.resourceservice.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableMethodSecurity
@Slf4j
public class SecurityConfig {

  @Value("${app.jwt.public-key-path}")
  String publicKeyPath;

  @Bean
  JwtDecoder jwtDecoder() throws Exception {
    log.info("Loading JWT public key from path: {}", publicKeyPath);
    byte[] x509 = Files.readAllBytes(Path.of(publicKeyPath));
    X509EncodedKeySpec spec = new X509EncodedKeySpec(x509);
    RSAPublicKey pk = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    return NimbusJwtDecoder.withPublicKey(pk).build();
  }

  @Bean
  SecurityFilterChain filterChain(HttpSecurity http,
                                  JwtDecoder decoder,
                                  Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthConverter) throws Exception {
    http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> {})
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/actuator/health").permitAll()
                    .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
                    .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth -> oauth
                    .jwt(jwt -> jwt
                            .decoder(decoder)
                            .jwtAuthenticationConverter(jwtAuthConverter)
                    )
            );
    log.info("Initializing SecurityFilterChain for Resource Service");
    return http.build();
  }

  @Bean
  JwtAuthenticationConverter jwtAuthenticationConverter() {
    log.info("Configuring JwtAuthenticationConverter with 'authorities' claim mapping");
    var granted = new JwtGrantedAuthoritiesConverter();
    granted.setAuthoritiesClaimName("authorities");
    granted.setAuthorityPrefix("");

    var converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(granted);
    return converter;
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    log.info("Setting up CORS configuration to allow all origins and methods for demo purposes");
    CorsConfiguration c = new CorsConfiguration();
    c.setAllowedOriginPatterns(List.of(
            "http://localhost:*",
            "https://*.github.io",
            "https://*.onrender.com"
    ));
    c.setAllowedMethods(List.of("GET","POST","PUT","DELETE","PATCH","OPTIONS"));
    c.setAllowedHeaders(List.of("Content-Type","Authorization"));
    c.setAllowCredentials(false);
    c.setMaxAge(Duration.ofHours(1));
    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
    src.registerCorsConfiguration("/**", c);
    return src;
  }
}
