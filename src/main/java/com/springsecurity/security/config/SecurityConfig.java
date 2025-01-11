package com.springsecurity.security.config;

import com.springsecurity.security.MyUserDetailsService;
import com.springsecurity.security.entity.Authorities;
import com.springsecurity.security.entity.Users;
import com.springsecurity.security.jwt.AuthEntryPointJwt;
import com.springsecurity.security.jwt.AuthTokenFilter;
import com.springsecurity.security.repo.AuthoritiesRepo;
import com.springsecurity.security.repo.UsersRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Autowired
    private DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;


    private AuthTokenFilter authTokenFilter;

    @Autowired
    public SecurityConfig(AuthTokenFilter authTokenFilter){
        this.authTokenFilter = authTokenFilter;
    }

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private AuthoritiesRepo authoritiesRepo;

    @Autowired
    private UsersRepo usersRepo;


    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/signin").permitAll()
                .requestMatchers("/signup").permitAll()
                .anyRequest()).authenticated());
        // http.formLogin(Customizer.withDefaults());
        //http.httpBasic(Customizer.withDefaults());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        http.csrf(csrf->csrf.disable());
        http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);
        return (SecurityFilterChain)http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(){
        return args -> {
            Users users = new Users();
            users.setUsername("mounesh");
            users.setPassword(passwordEncoder().encode("mounesh"));
            users.setEnabled(true);
            usersRepo.save(users);
            Authorities authorities = new Authorities();
            authorities.setAuthority("USER");
            authorities.setUser(users);
            authoritiesRepo.save(authorities);
            usersRepo.save(users);
        };
    }

//    @Bean
//    public CommandLineRunner initData(UserDetailsService userDetailsService) {
//        return args -> {
//            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
//            UserDetails user1 = User.withUsername("user1")
//                    .password(passwordEncoder().encode("password1"))
//                    .roles("USER")
//                    .build();
//            UserDetails admin = User.withUsername("admin")
//                    //.password(passwordEncoder().encode("adminPass"))
//                    .password(passwordEncoder().encode("adminPass"))
//                    .roles("ADMIN")
//                    .build();
//
//            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
//            userDetailsManager.createUser(user1);
//            userDetailsManager.createUser(admin);
//        };
//    }

    //below is the in memory
//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user1 = User.withUsername("admin").password("{noop}admin@123").roles("ADMIN").build();
//        UserDetails user2 = User.withUsername("user").password("{noop}user@123").roles("USER").build();
//        return new InMemoryUserDetailsManager(user1,user2);
//    }

    //database driven data - no encryption of password
//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user1 = User.withUsername("admin").password("{noop}admin@123").roles("ADMIN").build();
//        UserDetails user2 = User.withUsername("user").password("{noop}user@123").roles("USER").build();
//        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
//        jdbcUserDetailsManager.createUser(user1);
//        jdbcUserDetailsManager.createUser(user2);
//
//        return jdbcUserDetailsManager;
//    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user1 = User.withUsername("admin").password(passwordEncoder().encode("admin@123")).roles("ADMIN").build();
//        UserDetails user2 = User.withUsername("user").password(passwordEncoder().encode("user@123")).roles("USER").build();
//        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
//        jdbcUserDetailsManager.createUser(user1);
//        jdbcUserDetailsManager.createUser(user2);
//        return jdbcUserDetailsManager;
//    }


     @Bean
     public AuthenticationProvider authenticationProvider(){
         DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
         provider.setPasswordEncoder(passwordEncoder());
         provider.setUserDetailsService(userDetailsService);
         return provider;
     }



    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }


}
