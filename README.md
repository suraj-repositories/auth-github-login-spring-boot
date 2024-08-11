# auth-github-login-spring-boot
Login with GitHub basic implementation using spring boot

## Steps - 

- Step 1 : First you need a simple login system - I suggest you to take reference from [Role based login](https://github.com/suraj-repositories/auth-spring-security-3)

- Step 2 : Add dependency for oauth2client and spring security on your project 

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
	     
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>
		
<dependency>
	<groupId>org.thymeleaf.extras</groupId>
	<artifactId>thymeleaf-extras-springsecurity6</artifactId>
</dependency>

```


- Step 3 : Now you need to create credentials on github app
    - go to your github account settings
    - on the left sidebar `Developer settings` (bottom of list)
    - O-auth-apps -> new Oauth app
    - Fill the form details
      - homepage url = in my case `http://localhost:8080`. In deployed website it should be the website url
      - Authorization callback URL=  `http://localhost:8080/login/oauth2/code/github`
      - after filling all details click on finish
    - after that you can find the `Client ID` on your app page
    - you can generate the `Client secrets` by clicking on the button `Generate new client secret`
    - and the last thing is `Redirect URL` which is `http://localhost:8080/login/oauth2/code/github`
    
    
```bash
baseUrl: http://localhost:8080

spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: YOUR_GITHUB_CLIENT_ID
            client-secret: YOUR_GITHUB_CLIENT_PASSWORD
            redirect-uri: "{baseUrl}/login/oauth2/code/github"   # you redirect url here
            client-name: GitHub
            scope:
              - read:user
              - user:email
```

- Step 4 : you need to configure the oauth2client for github login : 

```java
package com.on11Aug24.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

@Configuration
@EnableWebSecurity
public class AuthConfig {
	
	@Autowired
	private UserDetailsService detailsService;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

		httpSecurity.csrf(Customizer.withDefaults())
                    .authorizeHttpRequests(request -> request
						.requestMatchers("/admin/**")
						.hasRole("ADMIN")
						.requestMatchers("/user/**")
						.hasAnyRole("USER", "ADMIN")
						.requestMatchers("/**")
						.permitAll()
						.anyRequest()
						.authenticated())
						.formLogin(form -> form
						.loginPage("/login")
						.loginProcessingUrl("/login")
						.usernameParameter("email")
						.passwordParameter("password")
						.defaultSuccessUrl("/")
						.permitAll())
                    .oauth2Login(form -> form
						.loginPage("/login")
						.defaultSuccessUrl("/login/github")        // we can create the custom controller for that URL
						.failureHandler(new SimpleUrlAuthenticationFailureHandler()))
                    .logout(logout -> logout
						.logoutSuccessUrl("/login?logout")
						.permitAll()
				);
	
		return httpSecurity.build();
	}

    @Bean
    static PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(detailsService).passwordEncoder(passwordEncoder());
	}
	
}

```

- Step 5 : On your custom login page you can use the given link to redirect to the github official login page

```html
	<a th:href="@{/oauth2/authorization/github}">Login with Github</a>
```


- Step 6 : the next step is to create controller methods to handle github login : 

```java
@GetMapping("/")
public String home(Model model, Authentication authentication,  HttpServletRequest request, HttpServletResponse response) {
	
	if (authentication != null) {
		User user = service.getUserByEmail(authentication.getName());
		if (user == null) {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			if (auth != null) {
				new SecurityContextLogoutHandler().logout(request, response, auth);
			}
		}
		model.addAttribute("user", user);
	}
	return "welcome";
}

```

```java
@GetMapping("/login/github")
public String loginWithGithub(OAuth2AuthenticationToken auth) {

	try {
		Map<String, Object> attributes = auth.getPrincipal().getAttributes();

		String name = (String) attributes.get("name");
		String email = (String) attributes.get("email");
		String picture = (String) attributes.get("avatar_url");

		LOGGER.info("{} - {} - {}", name, email, picture);

		User user = service.getUserByEmail(email);
		if (user == null) {
			String pass = UUID.randomUUID().toString();
			User createdUser = User.builder().name(name).email(email).picture(picture).id(null).password(pass).confirmPassword(pass)
					.dob(null).role("USER").build();
			user = service.saveUser(createdUser);
		}
		
		Authentication authentication = new UsernamePasswordAuthenticationToken(email, null, Collections.singleton(new SimpleGrantedAuthority("ROLE_" + user.getRole() )));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
	} catch (Exception e) {
		LOGGER.error("Authentication error while doing login : " + e.getMessage());
		return "redirect:/login";
	}

	return "redirect:/";
}

```

### File where i made changes 

- all files in src\main\java\com\on11Aug2024
- all files in src\main\resources\com\on11Aug2024
- src\main\resources\application.properties
- src\main\resources\application.yml
- pom.xml

### Need to make sure

- make sure to fit all the config details carefully like client-id, client-secret, redirect-url, base-url in `src\main\resources\application.yml` file
- never forget to create database with the given name if you are using this example

<br />
<br />
<p align="center">⭐️ Star my repositories if you find it helpful.</p>
<br />