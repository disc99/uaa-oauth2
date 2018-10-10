package com.example.uaaoauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@SpringBootApplication
@EnableAuthorizationServer
public class UaaApplication {

	public static void main(String[] args) {
		SpringApplication.run(UaaApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new Pbkdf2PasswordEncoder();
	}

	@Configuration
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Order(-20)
	static class LoginConfig extends WebSecurityConfigurerAdapter {

//		@Autowired
//		DataSource dataSource;
//		@Autowired
		UserDetailsService userDetailsService;

		LoginConfig(UserDetailsService userDetailsService) {
			super();
			this.userDetailsService = userDetailsService;
		}

		//		@Bean
//		PersistentTokenRepository persistentTokenRepository() {
//			JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
//			tokenRepository.setDataSource(dataSource);
//			return tokenRepository;
//		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.formLogin().loginPage("/login").permitAll().and().requestMatchers()
					.antMatchers("/", "/login", "/logout", "/oauth/authorize", "/oauth/confirm_access")
					.and().authorizeRequests().antMatchers("/login**").permitAll()
//					.antMatchers("/apps**").access("hasRole('ADMIN')").anyRequest()
//					.authenticated()
//					.and().rememberMe()
//					.tokenRepository(persistentTokenRepository())
					.and()
					.userDetailsService(userDetailsService)
//					.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(7)).and().logout()
//					.deleteCookies("JSESSIONID", "remember-me").permitAll().and().csrf()
					.csrf().ignoringAntMatchers("/oauth/**");
		}
	}

	@Configuration
	@EnableResourceServer
	static class ResourceServerConfig extends ResourceServerConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
					.authorizeRequests().mvcMatchers("/userinfo")
					.access("#oauth2.hasScope('read')");
		}
	}
}
