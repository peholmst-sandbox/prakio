package net.pkhapps.prakio;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import net.pkhapps.prakio.auth.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.PostConstruct;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfiguration.class);

    private Algorithm signingAlgorithm;
    private Algorithm verificationAlgorithm;

    @PostConstruct
    void init() throws Exception {
        // TODO In a real-world application, you would NOT re-generate the keys every time the application starts.
        // You would instead read them from some secure storage.
        LOGGER.info("Generating new key pair for use with JWTs");
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        final SecureRandom random = SecureRandom.getInstanceStrong();
        keyPairGenerator.initialize(2048, random);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        signingAlgorithm = Algorithm.RSA512((RSAPrivateKey) keyPair.getPrivate());
        verificationAlgorithm = Algorithm.RSA512((RSAPublicKey) keyPair.getPublic());
    }

    @Bean
    public JWTProperties jwtProperties() {
        return new JWTProperties();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        final JWTVerifier jwtVerifier = JWT
            .require(verificationAlgorithm)
            .withAudience(jwtProperties().getAudienceAsArray())
            .withIssuer(jwtProperties().getIssuer())
            .build();
        auth.authenticationProvider(new JWTAuthenticationProvider(jwtVerifier));
        // TODO Replace with real user database
        auth.inMemoryAuthentication()
            .withUser("joecool").password("password").authorities("ROLE_USER", "ROLE_ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(new JWTAuthenticationFilter(authenticationManager()),
            UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(new LoginFilter("/login", authenticationManager(),
                new JWTCreator(Clock.systemUTC(), signingAlgorithm, jwtProperties())),
            UsernamePasswordAuthenticationFilter.class);
        http.authorizeRequests().antMatchers("/*", "/bower_components/**", "/images/**", "/views/**").permitAll();

        // Require authentication for everything else
        http.authorizeRequests().anyRequest().authenticated();
        // Never create any HTTP sessions, the session is client-side only.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.csrf().disable();
    }
}
