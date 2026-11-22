package bdTrabalho.OngAplication.config;

import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

@Configuration
public class HttpClientConfig {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(3);
    private static final Duration READ_TIMEOUT = Duration.ofSeconds(5);

    /** Uso geral (ex.: ViaCEP). Sempre com timeout. */
    @Bean("restTemplate")
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder.connectTimeout(CONNECT_TIMEOUT).readTimeout(READ_TIMEOUT).build();
    }

    /** Fala com o provedor OIDC: timeouts + truststore próprio (bundle "oidc"). */
    @Bean("oidcRestTemplate")
    public RestTemplate oidcRestTemplate(RestTemplateBuilder builder, SslBundles sslBundles) {
        return builder
                .connectTimeout(CONNECT_TIMEOUT)
                .readTimeout(READ_TIMEOUT)
                .sslBundle(sslBundles.getBundle("oidc"))
                .build();
    }
}
