package com.example.hotsix.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .httpBasic().disable()
                .authorizeHttpRequests()
                .requestMatchers("/reissue").permitAll()
                .requestMatchers("/convert").permitAll()
                .anyRequest().authenticated()
                .and()
                .build();
    }
    
}
