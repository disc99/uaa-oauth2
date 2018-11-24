package com.example.uaaoauth2;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class UaaApplicationJwtAuthConfig {


    @Bean
    PasswordEncoder passwordEncoder() {
        return new Pbkdf2PasswordEncoder();
    }

    @Configuration
    static class WebMvcConfig implements WebMvcConfigurer {
        @Override
        public void addViewControllers(ViewControllerRegistry registry) {
            registry.addViewController("/login").setViewName("/login");
        }
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    @Order(-20)
    static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
        UserDetailsService userDetailsService;

        WebSecurityConfig(UserDetailsService userDetailsService) {
            super();
            this.userDetailsService = userDetailsService;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .formLogin()
                        .loginPage("/login").permitAll()
                        .and()
                    .requestMatchers()
                        .antMatchers("/", "/login", "/logout", "/oauth/authorize", "/oauth/confirm_access")
                        .and()
                    .authorizeRequests()
                        .antMatchers("/login**").permitAll()
                        .and()
                    .userDetailsService(userDetailsService)
                        .csrf().ignoringAntMatchers("/oauth/**")
            ;
        }

        @Bean
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }
    }

    // If customizing the feature, extend AuthorizationServerConfigurerAdapter.
    @Configuration
    @EnableAuthorizationServer
    static class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
        AuthenticationManager authenticationManager;

        public AuthorizationServerConfig(AuthenticationManager authenticationManager) {
            this.authenticationManager = authenticationManager;
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory().withClient("demo")
                    .secret("demo")
                    .scopes("read")
                    .autoApprove(true)
                    .authorizedGrantTypes("password", "authorization_code")
                    .redirectUris("http://localhost:8080/","http://localhost:8080/login","http://localhost:8080/login/oauth2/code/home")
            ;
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
            security
                    .passwordEncoder(passwordEncoder())
                    .checkTokenAccess("isAuthenticated()")
                    .tokenKeyAccess("permitAll()");
        }

        private PasswordEncoder passwordEncoder() {
            return new PasswordEncoder() {
                private final PasswordEncoder passwordEncoder = NoOpPasswordEncoder.getInstance();
                @Override
                public boolean matches(CharSequence rawPassword, String encodedPassword) {
                    return StringUtils.hasText(encodedPassword) ? passwordEncoder.matches(rawPassword, encodedPassword) : true;
                }
                @Override
                public String encode(CharSequence rawPassword) {
                    return passwordEncoder.encode(rawPassword);
                }
            };
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.authenticationManager(authenticationManager)
                    .accessTokenConverter(jwtAccessTokenConverter());
        }

        @ConfigurationProperties("jwt")
        @Bean
        JwtAccessTokenConverter jwtAccessTokenConverter() {
            return new JwtAccessTokenConverter();
        }
    }

    @Configuration
    @EnableResourceServer
    static class ResourceServerConfig extends ResourceServerConfigurerAdapter {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .sessionManagement()
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        .and()
                    .authorizeRequests()
                        .mvcMatchers("/userinfo").access("#oauth2.hasScope('read')")
            ;
        }
    }
}
