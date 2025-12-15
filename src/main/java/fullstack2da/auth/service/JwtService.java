package fullstack2da.auth.service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

import org.springframework.stereotype.Service;

import fullstack2da.auth.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
  private final byte[] secret;

  public JwtService() {
    String env = System.getenv("AUTH_JWT_SECRET");
    if (env == null || env.isBlank()) throw new RuntimeException("jwt_secret_missing");
    this.secret = env.getBytes(StandardCharsets.UTF_8);
  }

  public String generate(User user) {
    Instant now = Instant.now();
    return Jwts.builder()
      .setSubject(user.getEmail())
      .claim("id", user.getId())
      .claim("name", user.getName())
      .claim("roles", java.util.List.of(user.getRole()))
      .setIssuedAt(Date.from(now))
      .setExpiration(Date.from(now.plusSeconds(60L * 60L * 24L)))
      .signWith(Keys.hmacShaKeyFor(secret), SignatureAlgorithm.HS256)
      .compact();
  }

  public Claims parse(String token) {
    return Jwts.parserBuilder()
      .setSigningKey(Keys.hmacShaKeyFor(secret))
      .build()
      .parseClaimsJws(token)
      .getBody();
  }
}
