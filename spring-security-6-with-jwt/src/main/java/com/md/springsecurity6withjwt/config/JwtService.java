package com.md.springsecurity6withjwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Service
public class JwtService {

    /**
     * This is a Base64 encoded secret key used to sign the JWT. It ensures that the token is secure and cannot be tampered with.
     */
    private static final String SECRET_KEY = "6CFyZtybHW9KD3mGrBRVcuN2nm+gdP0Dbp9/S+5A8v86XC7R2R26n8QDastmuMZAxyT2ofC90nkzBCg6BkIOO04a1qm1Q0kc6TBAHzozJC8=";

    /**
     * This method extracts the username (or email) from the JWT.
     * It calls the extractClaim method, passing the token and a function to extract the subject claim, which holds the username.
     * @param token The JWT token
     * @return The username (or email) extracted from the JWT token
     */
    public String extractUsername(String token) {
        // the subject is the username/email
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * This is a generic method that takes a token and a function to resolve a specific claim from the token.
     * It calls extractAllClaims to get all the claims, then applies the provided function to extract the specific claim.
     * @param token The JWT token
     * @param claimsResolver A function that takes a Claims object and returns a specific claim
     * @return The specific claim extracted from the JWT token
     * @param <T> The type of the claim
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * This method extracts all the claims from the JWT.
     * It uses the Jwt's parser, sets the signing key, and parses the token to get the body, which contains all the claims.
     * @param token The JWT token
     * @return The body of the JWT token, which contains all the claims
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * This method decodes the SECRET_KEY from Base64 and returns a Key object used for signing and validating the JWT.
     * @return A Key object used for signing and validating the JWT
     */
    private Key getSigningKey() {
        byte[] keyByte = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyByte);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * The method takes two parameters: a map of extra claims and a UserDetails object.
     * The extra claims allow for additional information to be encoded into the token, such as roles or other custom attributes.
     * The UserDetails object provides information about the authenticated user, like the username.
     * The token is constructed with a subject (username), issued date, expiration date (10 hours from issuance), and is signed using HMAC SHA-256.
     * The resulting token is then returned as a compact string.
     * This method would typically be used after a user has successfully authenticated.
     * It generates a JWT that encodes the user's information and any additional claims, which can then be sent to the client to be included in subsequent requests.
     *
     * @param extraClaims extra claims to be encoded into the token
     * @param userDetails information about the authenticated user
     * @return a JWT token
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder() // Add any extra claims that were provided. This can include custom information like roles, permissions, etc.
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new java.util.Date(System.currentTimeMillis()))
                .setExpiration(new java.util.Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hours
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * This method takes a token and a UserDetails object.
     * It first extracts the username from the token, then checks if the username matches the username in the UserDetails object.
     * It also checks if the token has expired.
     * If the username matches and the token has not expired, the method returns true.
     *
     * @param token The JWT token
     * @param userDetails information about the authenticated user
     * @return true if the token is valid, false otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /**
     * This method takes a token and checks if it has expired.
     * It first extracts the expiration date from the token, then compares it to the current date.
     * If the expiration date is before the current date, the token has expired and the method returns true.
     * @param token The JWT token
     * @return true if the token has expired, false otherwise
     */
    private boolean isTokenExpired(String token) {
     return extractExpiration(token).before(new java.util.Date());
    }

    /**
     * This method takes a token and extracts the expiration date from it.
     * It uses the extractClaim method, passing the token and a function to extract the expiration date claim.
     * @param token The JWT token
     * @return The expiration date extracted from the JWT token
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
