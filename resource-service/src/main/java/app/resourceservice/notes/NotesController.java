package app.resourceservice.notes;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/notes")
@Slf4j
public class NotesController {

    private final Map<String, Note> store = new ConcurrentHashMap<>();

    @GetMapping
    public List<Note> list(@AuthenticationPrincipal Jwt jwt) {
        String user = jwt.getSubject();
        log.info("Listing notes for user: {}", user);
        return store.values().stream().filter(n -> n.getOwner().equals(user)).toList();
    }

    @PostMapping
    public Note create(@AuthenticationPrincipal Jwt jwt, @RequestBody Map<String, String> body) {
        String user = jwt.getSubject();
        log.info("Creating note for user: {} with title: {}", user, body.get("title"));
        Note saved = new Note(UUID.randomUUID().toString(), user, body.get("title"), body.get("content"));
        store.put(saved.getId(), saved);
        return saved;
    }
}