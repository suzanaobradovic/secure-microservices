package app.userservice.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// Repository interface for User entities, providing CRUD operations and username-based queries.
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);

  boolean existsByUsername(String username);
}
