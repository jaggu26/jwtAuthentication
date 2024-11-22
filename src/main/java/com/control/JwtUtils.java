package com.control;

import java.security.Key;
import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {

	// Base64 encoded secret key (as string)
    private static final String SECRET_KEY = "U29tZSByYW5kb20gdGV4dCBrZXkgY2VydCBkZWxpdmVyeXQ=";  // Base64 encoded secret key

    // Convert the string secret key into a Key object
    private static final Key KEY = Keys.hmacShaKeyFor(java.util.Base64.getDecoder().decode(SECRET_KEY));

    public String generateToken(String username) {
        // Create a JWT token with the given user information
        JwtBuilder builder = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))  // Token expiration (10 hours)
                .signWith(KEY);  // Use the Key object for signing

        return builder.compact();  // Build and return the compact JWT token string
    }


    public String extractUsername(String token) {
        // Parse the JWT token and extract the username
        Claims claims = Jwts.parser()
                .setSigningKey(KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();  // Extract and return the subject (username)
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return Jwts.parser()
                .setSigningKey(KEY)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
