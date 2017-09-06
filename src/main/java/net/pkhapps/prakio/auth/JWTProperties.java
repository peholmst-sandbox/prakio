package net.pkhapps.prakio.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public class JWTProperties {

    private int validityTimeMs;
    private String issuer;
    private String audience;
    private String audienceDelimiter = ",";

    public int getValidityTimeMs() {
        return validityTimeMs;
    }

    public void setValidityTimeMs(int validityTimeMs) {
        this.validityTimeMs = validityTimeMs;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAudience() {
        return audience;
    }

    public String[] getAudienceAsArray() {
        return audience.split(audienceDelimiter);
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getAudienceDelimiter() {
        return audienceDelimiter;
    }

    public void setAudienceDelimiter(String audienceDelimiter) {
        this.audienceDelimiter = audienceDelimiter;
    }
}
