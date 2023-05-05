package dev.paul.springbootsecurity.config;

import dev.paul.springbootsecurity.dao.UserDao;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final UserDao userDao;

    /***
     * Works well, but some of its methods have been deprecated and
     * others have better way of writing them in Spring Security 6.0
     * and Spring 3.
     *
     * Methods affected
     *
     * .csrf().disable() -- replaced with -- .csrf(csrf -> csrf().disable())
     *
     * .authorizeRequests() -- replaced with --
     *
     *      .authorizeHttpRequests(auth -> auth
     *           .requestMatchers("/api/v1/auth/**").permitAll()
     *           .anyRequests().authenticated();
     *       )
     *
     * .antMatchers() -- replaced -- requestMatchers(). Now applied inside authorizeHttpRequests() lambda.
     *
     * .permitAll(), .anyRequests(), and .authenticated() applied inside authorizeHttpRequests() lambda.
     *
     * .sessionManagement() now has sessionCreationPolicy() in its lambda DSL
     *       .sessionManagement(session -> session
     *            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
     *       )
     *
     *
     * In the Lambda DSL there is no need to chain configuration options using the .and() method.
     * The HttpSecurity instance is automatically returned for further configuration after the call.
     * For more information -> https://spring.io/blog/2019/11/21/spring-security-lamda-dsl
     *
     * For more reference -> https://stackoverflow.com/questions/74683225/updating-to-spring-security-6-0-replacing-removed-and-deprecated-functionality
     *
     * @Bean
     *     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
     *         http
     *                 .csrf().disable()
     *                 .authorizeRequests()
     *                 //.antMatchers("/**///auth/**") -deprecated in Spring Security 6.0
     /***
     *                 .requestMatchers("/api/v1/auth/**")
     *                 .permitAll()
     *                 .anyRequest()
     *                 .authenticated()
     *                 .and()
     *                 // we need to add session creation policy. How we want to handle the session creation within our security/authentication - very important
     *                 .sessionManagement()
     *                 .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
     *                 .and()
     *                 // we tell spring to use the UserDetailsService implementation we provided
     *                 .authenticationProvider(authenticationProvider())
     *                 // we need to tell Spring to use our filter -> [JwtAuthFilter]. Done below
     *                 .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // we want to add filer before another
     *         return http.build();
     *     }
     *
     * @return
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/v1/auth/**").permitAll()
                    .anyRequest().authenticated()
            )
            // we need to add session creation policy - How we want to handle the session creation
            // within our security/authentication - very important
            .sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // we tell spring to use the UserDetailsService implementation we provided
            .authenticationProvider(authenticationProvider())
            // we need to tell Spring to use our filter -> [JwtAuthFilter]. Done below
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // we want to add filer before another
        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public  PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); // if you don't care about password encryption
        // to encrypt password, we use
        // return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
                return userDao.findUserByEmail(email);
            }
        };
    }
}
