package com.md.springsecurity6withjwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor // generates a constructor with one parameter for each field that requires special handling
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /**
     * This is an injected instance of the JwtService class, used to perform JWT-related operations.
     */
    private final JwtService jwtService;

    /**
     * we will be using a custom UserDetailsService implementation that will be used to load user-specific data in the security framework.
     */
    private final UserDetailsService userService;

    /**
     * This method is called for every request. It performs the following actions:
     * Extracts the "Authorization" header from the request.
     * If the header is not present or doesn't start with "Bearer", it continues the filter chain without processing the token.
     * If the header is present, it extracts the JWT by removing the "Bearer" part.
     * Extracts the user email (or username) from the token using jwtService.extractUsername.
     *
     * @param request     The HTTP request
     * @param response    The HTTP response
     * @param filterChain The filter chain to continue processing the request and response through the filter chain (if the token is valid)
     * @throws ServletException thrown if the request for the POST could not be handled
     * @throws IOException      thrown if an input or output error is detected when the filter handles the request
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // This header contains the jwt token
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // If the header is not null and starts with "Bearer" then we extract the token
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        // Extract the token - remove the "Bearer" part (seven characters)
        jwt = authHeader.substring(7);
        // Extract the user email from the token
        userEmail = jwtService.extractUsername(jwt);

        // If the user email is not null and the security context does not contain an authentication object
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Get the user details from the user service
            final UserDetails userDetails = userService.loadUserByUsername(userEmail);

            // If the token is valid, set the authentication object in the security context
            if (jwtService.isTokenValid(jwt, userDetails)) {

                final UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication object in the security context
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // Continue processing the request and response
        filterChain.doFilter(request, response);
    }
}
