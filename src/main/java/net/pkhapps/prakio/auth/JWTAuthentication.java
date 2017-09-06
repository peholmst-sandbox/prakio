package net.pkhapps.prakio.auth;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

public class JWTAuthentication implements Authentication {

    static final String AUTH_CLAIM = "auth";

    private final DecodedJWT verifiedToken;
    private final String token;
    private boolean authenticated;
    private Collection<? extends GrantedAuthority> authorities;

    public JWTAuthentication(DecodedJWT token) {
        this.verifiedToken = Objects.requireNonNull(token);
        this.token = verifiedToken.getToken();
        this.authenticated = true;
        this.authorities = Optional.ofNullable(token.getClaim(AUTH_CLAIM).asString())
            .map(AuthorityUtils::commaSeparatedStringToAuthorityList).map(Collections::unmodifiableList)
            .orElse(Collections.emptyList());
    }

    public JWTAuthentication(String token) {
        this.verifiedToken = null;
        this.token = Objects.requireNonNull(token);
        this.authenticated = false;
        this.authorities = Collections.emptySet();
    }

    public String getToken() {
        return token;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return getToken();
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return verifiedToken;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Cannot set authenticated flag to true");
        }
        this.authenticated = false;
    }

    @Override
    public String getName() {
        return verifiedToken == null ? null : verifiedToken.getSubject();
    }
}
