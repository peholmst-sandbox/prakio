package net.pkhapps.prakio.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LoginFilter extends AbstractAuthenticationProcessingFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTCreator jwtCreator;

    public LoginFilter(String defaultFilterProcessesUrl,
        AuthenticationManager authenticationManager, JWTCreator jwtCreator) {
        super(defaultFilterProcessesUrl);
        this.authenticationManager = authenticationManager;
        this.jwtCreator = jwtCreator;
    }

    public LoginFilter(RequestMatcher requiresAuthenticationRequestMatcher,
        AuthenticationManager authenticationManager, JWTCreator jwtCreator) {
        super(requiresAuthenticationRequestMatcher);
        this.authenticationManager = authenticationManager;
        this.jwtCreator = jwtCreator;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException, IOException, ServletException {
        final String username = request.getParameter("username");
        final String password = request.getParameter("password");
        final UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username,
            password);
        return authenticationManager.authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
        Authentication authResult) throws IOException, ServletException {
        final String token = jwtCreator.createToken(authResult);
        JWTUtils.writeToken(response, token);
    }
}
