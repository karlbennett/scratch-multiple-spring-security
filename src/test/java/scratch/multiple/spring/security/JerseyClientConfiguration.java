package scratch.multiple.spring.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientResponseFilter;
import javax.ws.rs.core.NewCookie;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static javax.ws.rs.core.HttpHeaders.COOKIE;

@Configuration
public class JerseyClientConfiguration {

    @Bean
    public Client client1() {
        return ClientBuilder.newBuilder().register(new CookieFilter()).build();
    }

    @Bean
    public Client client2() {
        return ClientBuilder.newBuilder().register(new CookieFilter()).build();
    }

    @Bean
    public Client client3() {
        return ClientBuilder.newBuilder().register(new CookieFilter()).build();
    }

    private static class CookieFilter implements ClientRequestFilter, ClientResponseFilter {

        private Map<String, NewCookie> cookies = new HashMap<>();

        @Override
        public void filter(ClientRequestContext requestContext) throws IOException {
            requestContext.getHeaders().put(COOKIE, new ArrayList<>(cookies.values()));
        }

        @Override
        public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext)
            throws IOException {
            cookies.putAll(responseContext.getCookies());
        }
    }
}
