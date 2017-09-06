package net.pkhapps.prakio.auth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

public final class JWTUtils {

    private JWTUtils() {
    }

    public static void writeToken(HttpServletResponse response, String token) {
        response.setHeader("Authorization", String.format("Bearer %s", token));
    }

    public static Optional<String> readToken(HttpServletRequest request) {
        final String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return Optional.empty();
        } else {
            return Optional.of(header.substring(7));
        }
    }
}
