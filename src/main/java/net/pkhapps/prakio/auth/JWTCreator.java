package net.pkhapps.prakio.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import java.sql.Date;
import java.time.Clock;
import java.time.Instant;

public class JWTCreator {

    private final Clock clock;
    private final Algorithm algorithm;
    private final JWTProperties jwtProperties;

    public JWTCreator(Clock clock, Algorithm algorithm, JWTProperties jwtProperties) {
        this.clock = clock;
        this.algorithm = algorithm;
        this.jwtProperties = jwtProperties;
    }

    public String createToken(Authentication authentication) {
        Instant now = clock.instant();
        Instant expires = now.plusMillis(jwtProperties.getValidityTimeMs());

        return JWT.create()
            .withAudience(jwtProperties.getAudienceAsArray())
            .withExpiresAt(Date.from(expires))
            .withNotBefore(Date.from(now))
            .withIssuedAt(Date.from(now))
            .withIssuer(jwtProperties.getIssuer())
            .withSubject(authentication.getName())
            .withClaim(JWTAuthentication.AUTH_CLAIM,
                String.join(",", AuthorityUtils.authorityListToSet(authentication.getAuthorities())))
            .sign(algorithm);
    }
}
