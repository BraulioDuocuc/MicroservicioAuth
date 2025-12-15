package fullstack2da.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import fullstack2da.auth.dto.LoginRequest;
import fullstack2da.auth.dto.RegisterRequest;
import fullstack2da.auth.dto.UserDTO;
import fullstack2da.auth.dto.AuthResponse;
import fullstack2da.auth.model.User;
import fullstack2da.auth.service.UserService;
import fullstack2da.auth.service.JwtService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = {"http://localhost:5173", "http://mainfullstackexamen.s3-website-us-east-1.amazonaws.com", "https://mainfullstackexamen.s3-website-us-east-1.amazonaws.com"})
public class AuthController {
  private final UserService service;
  private final JwtService jwt;

  public AuthController(UserService service, JwtService jwt) {
    this.service = service;
    this.jwt = jwt;
  }

  @PostMapping("/register")
  public ResponseEntity<AuthResponse> register(@Validated @RequestBody RegisterRequest req) {
    try {
      User u = service.register(req);
      String token = jwt.generate(u);
      AuthResponse dto = new AuthResponse();
      dto.setId(u.getId());
      dto.setName(u.getName());
      dto.setEmail(u.getEmail());
      dto.setCreatedAt(u.getCreatedAt());
      dto.setToken(token);
      dto.setRole(u.getRole());
      return ResponseEntity.status(HttpStatus.CREATED).body(dto);
    } catch (RuntimeException e) {
      if ("email_taken".equals(e.getMessage())) return ResponseEntity.status(HttpStatus.CONFLICT).build();
      return ResponseEntity.badRequest().build();
    }
  }

  @PostMapping("/login")
  public ResponseEntity<AuthResponse> login(@Validated @RequestBody LoginRequest req) {
    try {
      User u = service.login(req.getEmail(), req.getPassword());
      String token = jwt.generate(u);
      AuthResponse dto = new AuthResponse();
      dto.setId(u.getId());
      dto.setName(u.getName());
      dto.setEmail(u.getEmail());
      dto.setCreatedAt(u.getCreatedAt());
      dto.setToken(token);
      dto.setRole(u.getRole());
      return ResponseEntity.ok(dto);
    } catch (RuntimeException e) {
      if ("invalid_credentials".equals(e.getMessage())) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
      return ResponseEntity.notFound().build();
    }
  }

  @PostMapping("/refresh")
  public ResponseEntity<AuthResponse> refresh(@RequestHeader(name = "Authorization", required = false) String auth) {
    if (auth == null || !auth.startsWith("Bearer ")) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    String token = auth.substring(7);
    try {
      io.jsonwebtoken.Claims claims = jwt.parse(token);
      String email = claims.getSubject();
      User u = service.getByEmail(email);
      String newToken = jwt.generate(u);
      AuthResponse dto = new AuthResponse();
      dto.setId(u.getId());
      dto.setName(u.getName());
      dto.setEmail(u.getEmail());
      dto.setCreatedAt(u.getCreatedAt());
      dto.setToken(newToken);
      dto.setRole(u.getRole());
      return ResponseEntity.ok(dto);
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
  }

  @GetMapping("/me")
  public ResponseEntity<UserDTO> me(@RequestHeader(name = "Authorization", required = false) String auth) {
    if (auth == null || !auth.startsWith("Bearer ")) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    String token = auth.substring(7);
    try {
      io.jsonwebtoken.Claims claims = jwt.parse(token);
      String email = claims.getSubject();
      User u = service.getByEmail(email);
      UserDTO dto = new UserDTO();
      dto.setId(u.getId());
      dto.setName(u.getName());
      dto.setEmail(u.getEmail());
      dto.setCreatedAt(u.getCreatedAt());
      return ResponseEntity.ok(dto);
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
  }

  @PutMapping("/users/{id}/role")
  public ResponseEntity<UserDTO> setRole(
    @PathVariable("id") Long id,
    @RequestParam(name = "role") String role,
    @RequestHeader(name = "Authorization", required = false) String auth
  ) {
    if (auth == null || !auth.startsWith("Bearer ")) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    try {
      io.jsonwebtoken.Claims claims = jwt.parse(auth.substring(7));
      Object roles = claims.get("roles");
      java.util.List<?> list = roles instanceof java.util.List<?> l ? l : java.util.List.of(roles);
      boolean isAdmin = list != null && list.stream().anyMatch(r -> String.valueOf(r).equals("ADMIN"));
      if (!isAdmin) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
      User u = service.setRole(id, role);
      UserDTO dto = new UserDTO();
      dto.setId(u.getId());
      dto.setName(u.getName());
      dto.setEmail(u.getEmail());
      dto.setCreatedAt(u.getCreatedAt());
      return ResponseEntity.ok(dto);
    } catch (RuntimeException e) {
      if ("invalid_role".equals(e.getMessage())) return ResponseEntity.badRequest().build();
      return ResponseEntity.notFound().build();
    }
  }
}
