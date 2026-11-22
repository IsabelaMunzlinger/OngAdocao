package bdTrabalho.OngAplication.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "oidc")
public record OidcProperties(
        String issuer,
        String authorizationEndpoint,
        String tokenEndpoint,
        String userinfoEndpoint,
        String jwksUri,
        String endSessionEndpoint,
        String postLogoutRedirectUri,
        String clientId,
        String clientSecret,
        String redirectUri,
        boolean autoProvision,
        int absoluteSessionHours
) {}
