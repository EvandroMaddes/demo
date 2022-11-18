package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.demo.security.ApplicationUserPermission.*;
import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
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
//                                no more useful with preAuthorize tag
//                                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                                .anyRequest()
                                .authenticated()
                )
                    .formLogin()
                    .loginPage("/login").permitAll()
                    .defaultSuccessUrl("/courses",true)
                    .passwordParameter("password") //it's already set by defualt to this value, same name as in the html page
                    .usernameParameter("username") //it's already set by defualt to this value, same name as in the html page
                .and()
                    .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                    .key("encryptionKeyForMD%PairUsernameExpTime")
                    .rememberMeParameter("remember-me") //it's already set by defualt to this value, same name as in the html page
                .and()
                    .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", HttpMethod.POST.name()))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");
        return http.build();


    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails studentUser = User.builder()
                .username("Student")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails adminUser = User.builder()
                .username("Admin")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails adminTraineeUser = User.builder()
                .username("AdminTrainee")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();
        return new InMemoryUserDetailsManager(
                studentUser,
                adminUser,
                adminTraineeUser);
    }

}
