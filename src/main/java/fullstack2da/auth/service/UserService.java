package fullstack2da.auth.service;

import java.time.LocalDateTime;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import fullstack2da.auth.dto.RegisterRequest;
import fullstack2da.auth.model.User;
import fullstack2da.auth.repository.UserRepository;

@Service
@Transactional
public class UserService {
  private final UserRepository users;
  private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

  public UserService(UserRepository users) {
    this.users = users;
  }

  public User register(RegisterRequest req) {
    if (users.existsByEmail(req.getEmail())) throw new RuntimeException("email_taken");
    User u = new User();
    u.setName(req.getName());
    u.setEmail(req.getEmail());
    u.setPasswordHash(encoder.encode(req.getPassword()));
    u.setCreatedAt(LocalDateTime.now());
    u.setRole("USER");
    return users.save(u);
  }

  public User login(String email, String password) {
    User u = users.findByEmail(email).orElseThrow(() -> new RuntimeException("not_found"));
    if (!encoder.matches(password, u.getPasswordHash())) throw new RuntimeException("invalid_credentials");
    return u;
  }

  public User getByEmail(String email) {
    return users.findByEmail(email).orElseThrow(() -> new RuntimeException("not_found"));
  }

  public User setRole(Long userId, String role) {
    if (!"ADMIN".equals(role) && !"USER".equals(role)) throw new RuntimeException("invalid_role");
    User u = users.findById(userId).orElseThrow(() -> new RuntimeException("not_found"));
    u.setRole(role);
    return users.save(u);
  }
}
