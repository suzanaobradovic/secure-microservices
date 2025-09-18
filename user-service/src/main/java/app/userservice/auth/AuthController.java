package app.userservice.auth;

import app.userservice.security.JwtService;
import app.userservice.user.User;
import app.userservice.user.UserRepository;
import java.util.Set;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthController {

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;

    public AuthController(UserRepository users, PasswordEncoder encoder, JwtService jwt) {
        this.users = users; this.encoder = encoder; this.jwt = jwt;
    }

    @PostMapping("/register")
    @Transactional
    public void register(@RequestBody Credentials credentials)  {
        log.info("Register request received for username: {}", credentials.getUsername());
        if (users.existsByUsername(credentials.getUsername())) throw new IllegalArgumentException("username_taken");
        User u = new User();
        u.setUsername(credentials.getUsername());
        u.setPasswordHash(encoder.encode(credentials.getPassword()));
        u.setRoles(Set.of("ROLE_USER"));
        users.save(u);
    }

    @PostMapping("/login")
    public String login(@RequestBody Credentials credentials) throws Exception {
        log.info("Login attempt for username: {}", credentials.getUsername());
        User u = users.findByUsername(credentials.getUsername()).orElseThrow(() -> new IllegalArgumentException("bad_credentials"));
        if (!encoder.matches(credentials.getPassword(), u.getPasswordHash())) throw new IllegalArgumentException("bad_credentials");
        return jwt.createToken(u.getUsername(), u.getRoles().stream().toList());
    }
}