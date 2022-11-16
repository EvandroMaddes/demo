package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.example.demo.security.ApplicationUserPermission.*;
import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests(
                        (authz) -> authz
                                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //Accessible
                                .antMatchers("/api/**").hasRole(STUDENT.name())
                                .antMatchers(HttpMethod.DELETE,"/managment/api/**").hasAuthority(COURSE_WRITE.name())
                                .antMatchers(HttpMethod.POST,"/managment/api/**").hasAuthority(COURSE_WRITE.name())
                                .antMatchers(HttpMethod.PUT,"/managment/api/**").hasAuthority(COURSE_WRITE.name())
                                .antMatchers(HttpMethod.GET,"/managment/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                                .anyRequest()
                                .authenticated()
                )
                .httpBasic();
        return http.build();


    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails evandroUser = User.builder()
                .username("Evandro")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedGrantedAuthorities())
                .build();

        UserDetails angelaUser = User.builder()
                .username("Angela")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedGrantedAuthorities())
                .build();

        UserDetails emanueleUser = User.builder()
                .username("Emanuele")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantedGrantedAuthorities())
                .build();
        return new InMemoryUserDetailsManager(
                evandroUser,
                angelaUser,
                emanueleUser);
    }

}
