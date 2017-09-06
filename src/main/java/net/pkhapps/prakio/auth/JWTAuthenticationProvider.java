package net.pkhapps.prakio.auth;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class JWTAuthenticationProvider implements AuthenticationProvider {

    private final JWTVerifier jwtVerifier;

    public JWTAuthenticationProvider(JWTVerifier jwtVerifier) {
        this.jwtVerifier = jwtVerifier;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof JWTAuthentication) {
            JWTAuthentication jwtAuthentication = (JWTAuthentication) authentication;
            try {
                DecodedJWT verifiedToken = jwtVerifier.verify(jwtAuthentication.getToken());
                return new JWTAuthentication(verifiedToken);
            } catch (JWTVerificationException ex) {
                throw new BadCredentialsException("Could not verify JWT", ex);
            }
        } else {
            throw new IllegalArgumentException("Only JWTAuthentication is supported");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JWTAuthentication.class.isAssignableFrom(authentication);
    }
}
