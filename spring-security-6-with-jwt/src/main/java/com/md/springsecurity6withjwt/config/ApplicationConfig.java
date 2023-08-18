package com.md.springsecurity6withjwt.config;

import com.md.springsecurity6withjwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor // generates a constructor with a parameter for each field in your class.
public class ApplicationConfig {

    private final UserRepository userRepository;

    /**
     * UserDetailsService is an interface that is used to retrieve user-related data.
     * It has a single method that loads a user based on the username.
     * @return UserDetailsService object that is used to retrieve user-related data.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User " + username + " not found"));
    }

    /**
     * This AuthenticationProvider is the data access object that is responsible for reading the user credentials from the database.
     * It also encodes the password and compares it with the password that is sent in the request.
     * There are many implementations of AuthenticationProvider, but we will be using DaoAuthenticationProvider.
     * @return AuthenticationProvider object that is responsible for reading the user credentials from the database.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        // Need to specify which UserDetailsService to use.
        // (There could be multiple implementations of UserDetailsService, such as one that reads username from a database and another that reads from an LDAP server).
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * AuthenticationManager is the interface that is used to authenticate a user.
     * It has a single method that authenticates a user based on the Authentication object.
     * AuthenticationManager is used by the AuthenticationProvider to authenticate a user.
     * @param config AuthenticationConfiguration object that is used to authenticate a user.
     * @return AuthenticationManager object that is used to authenticate a user.
     * @throws Exception if there is an error while authenticating the user.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * PasswordEncoder is used to encode the password before storing it in the database.
     * @return PasswordEncoder object that is used to encode the password before storing it in the database.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
