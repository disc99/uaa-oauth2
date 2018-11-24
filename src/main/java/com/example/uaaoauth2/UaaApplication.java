package com.example.uaaoauth2;

import org.apache.catalina.filters.RequestDumperFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.authserver.AuthorizationServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import javax.sql.DataSource;
import java.util.concurrent.TimeUnit;

@SpringBootApplication
public class UaaApplication {

	public static void main(String[] args) {
		SpringApplication.run(UaaApplication.class, args);
	}

	@Bean
	RequestDumperFilter requestDumperFilter() {
		return new RequestDumperFilter();
	}















//
//	@Bean
//	RequestDumperFilter requestDumperFilter() {
//		return new RequestDumperFilter();
//	}
//
//	@Bean
//	PasswordEncoder passwordEncoder() {
//		return new Pbkdf2PasswordEncoder();
//	}
//
//	@Configuration
//	static class WebMvcConfig implements WebMvcConfigurer {
//		@Override
//		public void addViewControllers(ViewControllerRegistry registry) {
//			registry.addViewController("/login").setViewName("/login");
//		}
//	}
//
//	@Configuration
//	@EnableGlobalMethodSecurity(prePostEnabled = true)
//	@Order(-20)  // prior to AuthorizationServerSecurityConfiguration (order = 0)
//	static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
//
//		DataSource dataSource;
//		UserDetailsService userDetailsService;
//
//		@SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
//		WebSecurityConfig(DataSource dataSource, UserDetailsService userDetailsService) {
//			super();
//			this.dataSource = dataSource;
//			this.userDetailsService = userDetailsService;
//		}
//
////		@Bean
////		PersistentTokenRepository persistentTokenRepository() {
////			JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
////			tokenRepository.setDataSource(dataSource);
////			return tokenRepository;
////		}
//
//		@Override
//		protected void configure(HttpSecurity http) throws Exception {
//			http.formLogin().loginPage("/login").permitAll()
//					.and()
//						.requestMatchers()
//						.antMatchers("/", "/login", "/logout", "/oauth/authorize", "/oauth/confirm_access")
//					.and()
//						.authorizeRequests()
//						.antMatchers("/login**")
//						.permitAll()
////					.antMatchers("/apps**").access("hasRole('ADMIN')").anyRequest()
////					.authenticated()
////					.and()
////						.rememberMe()
////						.tokenRepository(persistentTokenRepository())
//					.and()
////						.userDetailsService(userDetailsService)
//						.csrf()
//						.ignoringAntMatchers("/oauth/**")
////					.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(7)).and().logout()
////					.deleteCookies("JSESSIONID", "remember-me").permitAll().and()
//			;
//		}
//
//		@Bean
//		public AuthenticationManager authenticationManagerBean() throws Exception {
//			return super.authenticationManagerBean();
//		}
//	}
//
//	@Configuration
//	@EnableAuthorizationServer
//	@EnableConfigurationProperties({AuthorizationServerProperties.class})
//	static class OAuth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {
//		@Autowired
//		AuthenticationManager authenticationManager;
//		@Autowired
//		AuthorizationServerProperties authorizationServerProperties;
//
//		@Override
//		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//			clients.inMemory()
//					.withClient("demo")
//					.secret("demo")
//					.authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
//					.scopes("read", "write")
//					.accessTokenValiditySeconds((int) TimeUnit.HOURS.toSeconds(1))
//					.autoApprove(true)
//					.redirectUris("http://localhost:8080/","http://localhost:8080/login","http://localhost:8080/login/oauth2/code/home")
//			;
//		}
//
//		@Override
//		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//			endpoints.authenticationManager(authenticationManager).accessTokenConverter(jwtAccessTokenConverter());
//		}
//
//		@Override
//		public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//			security.tokenKeyAccess(authorizationServerProperties.getTokenKeyAccess());
//		}
//
//		@Bean
//		@ConfigurationProperties("jwt")
//		JwtAccessTokenConverter jwtAccessTokenConverter() {
//			return new JwtAccessTokenConverter();
//		}
//	}
//
//
////
////	// If customizing the feature, extends AuthorizationServerConfigurerAdapter.
////	@Configuration
////	@EnableAuthorizationServer
////	static class AuthorizationServerConfig
////			extends AuthorizationServerConfigurerAdapter {
////		AuthenticationManager authenticationManager;
////		DataSource dataSource;
////
//////		public AuthorizationServerConfig(AuthenticationManager authenticationManager) {
//////			this.authenticationManager = authenticationManager;
//////		}
////
////		public AuthorizationServerConfig(AuthenticationManager authenticationManager, DataSource dataSource) {
////			this.authenticationManager = authenticationManager;
////			this.dataSource = dataSource;
////		}
////
////		@Override
////		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
////			clients.inMemory()
////					.withClient("demo")
////					.secret("demo")
////					.scopes("openid", "read", "write")
////					.autoApprove(true)
////					.authorizedGrantTypes("password", "authorization_code")
////					.redirectUris("http://localhost:8080/","http://localhost:8080/login","http://localhost:8080/login/oauth2/code/home")
////			;
////		}
////
////		@Override
////		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
////			endpoints
////					.tokenStore(tokenStore())
////					.tokenEnhancer(jwtTokenEnhancer())
////					.authenticationManager(authenticationManager)
////			;
////		}
////
////		@Bean
////		public TokenStore tokenStore() {
////			JwtTokenStore jwtTokenStore = new JwtTokenStore(jwtTokenEnhancer());
//////			jwtTokenStore.setApprovalStore(approvalStore());
////			return jwtTokenStore;
////		}
////
//////		@Bean
//////		public ApprovalStore approvalStore() {
//////			JdbcApprovalStore jdbcApprovalStore = new JdbcApprovalStore(dataSource);
//////			return jdbcApprovalStore;
//////		}
////
////		@Bean
////		@ConfigurationProperties("jwt")
////		JwtAccessTokenConverter jwtTokenEnhancer() {
////			return new JwtAccessTokenConverter();
////		}
////	}
//
//	@Configuration
//	@EnableResourceServer
//	static class ResourceServerConfig extends ResourceServerConfigurerAdapter {
//		@Override
//		public void configure(HttpSecurity http) throws Exception {
//			http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//					.and()
//						.authorizeRequests()
//						.mvcMatchers("/userinfo")
//						.access("#oauth2.hasScope('read')");
//		}
//
//	}





//
//	@Configuration
//	static class MvcConfig extends WebMvcConfigurerAdapter {
//		@Override
//		public void addViewControllers(ViewControllerRegistry registry) {
//			registry.addViewController("login").setViewName("login");
//			registry.addViewController("/").setViewName("index");
//		}
//	}
//
//	@Configuration
//	@EnableAuthorizationServer
//	@EnableConfigurationProperties({AuthorizationServerProperties.class})
//	static class OAuth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {
//		@Autowired
//		AuthenticationManager authenticationManager;
//		@Autowired
//		AuthorizationServerProperties authorizationServerProperties;
//
//		@Override
//		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//			clients.inMemory()
//					.withClient("demo")
//					.secret("demo")
//					.authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
//					.scopes("read", "write")
//					.accessTokenValiditySeconds((int) TimeUnit.HOURS.toSeconds(1))
//					.autoApprove(true)
//					.redirectUris("http://localhost:8080/","http://localhost:8080/login","http://localhost:8080/login/oauth2/code/home")
//			;
//		}
//
////		@Override
////		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
////			endpoints.authenticationManager(authenticationManager).accessTokenConverter(jwtAccessTokenConverter());
////		}
//
//		@Override
//		public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//			security.tokenKeyAccess(authorizationServerProperties.getTokenKeyAccess());
//		}
//
////		@Bean
////		@ConfigurationProperties("jwt")
////		JwtAccessTokenConverter jwtAccessTokenConverter() {
////			return new JwtAccessTokenConverter();
////		}
//	}
//
//
//	@Configuration
//	@Order(-20)
//	static class LoginConfig extends WebSecurityConfigurerAdapter {
//		@Override
//		protected void configure(HttpSecurity http) throws Exception {
//			http
//					.formLogin().loginPage("/login").permitAll()
//					.and()
//					.requestMatchers()
//					.antMatchers("/", "/login", "/oauth/authorize", "/oauth/confirm_access")
//					.and()
//					.authorizeRequests()
//					.anyRequest().authenticated();
//		}
//		@Bean
//		public AuthenticationManager authenticationManagerBean() throws Exception {
//			return super.authenticationManagerBean();
//		}
//
//	}
//
//	@Bean
//	RequestDumperFilter requestDumperFilter() {
//		return new RequestDumperFilter();
//	}
//
//	@Bean
//	PasswordEncoder passwordEncoder() {
//		return NoOpPasswordEncoder.getInstance();
//	}

}
