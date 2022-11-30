package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtTokenVerified;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;

import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {
    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;


    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService,
                                     JwtConfig jwtConfig,
                                     SecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerified(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeHttpRequests(
                        (authz) -> authz
                                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //Accessible
                                .antMatchers("/api/**").hasRole(STUDENT.name())
                                //no more useful with preAuthorize tag
                                //.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                                //.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                                //.antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                                //.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                                .anyRequest()
                                .authenticated()
                );
        //form based auth
        //.formLogin()
        //.loginPage("/login").permitAll()
        //.defaultSuccessUrl("/courses", true)
        //.passwordParameter("password") //it's already set by defualt to this value, same name as in the html page
        //.usernameParameter("username") //it's already set by defualt to this value, same name as in the html page
        //.and()
        //.rememberMe()
        //.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
        //.key("encryptionKeyForMD%PairUsernameExpTime")
        //.rememberMeParameter("remember-me") //it's already set by defualt to this value, same name as in the html page
        //.and()
        //.logout()
        //.logoutUrl("/logout")
        //.logoutRequestMatcher(new AntPathRequestMatcher("/logout", HttpMethod.POST.name()))
        //.clearAuthentication(true)
        //.invalidateHttpSession(true)
        //.deleteCookies("JSESSIONID", "remember-me")
        //.logoutSuccessUrl("/login");
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return new ProviderManager(provider);
    }


}


