package app.userservice.auth;

import lombok.Data;

// Simple DTO that holds a user's login credentials (username and password) used during authentication and registration requests.
@Data
public class Credentials {
  public String username;
  public String password;
}
