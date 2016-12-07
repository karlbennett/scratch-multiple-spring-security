package scratch.multiple.spring.security;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.ws.rs.client.Client;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static javax.ws.rs.client.Entity.form;
import static javax.ws.rs.core.Response.Status.OK;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class ITMultipleLogin {

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private Client client1;

    @Autowired
    private Client client2;

    @Autowired
    private Client client3;

    private String baseUrl;

    @Before
    public void setUp() {
        baseUrl = "http://localhost:" + port;
    }

    @Test
    public void Cannot_access_a_secure_endpoint() {

        // When
        final Response secure1 = client1.target(baseUrl).path("one").path("secure").request().get();
        final Response secure2 = client2.target(baseUrl).path("two").path("secure").request().get();
        final Response secure3 = client3.target(baseUrl).path("secure").request().get();

        // Then
        assertThat(secure1.getStatus(), is(UNAUTHORIZED.getStatusCode()));
        assertThat(secure2.getStatus(), is(UNAUTHORIZED.getStatusCode()));
        assertThat(secure3.getStatus(), is(UNAUTHORIZED.getStatusCode()));
    }

    @Test
    public void Can_login_and_access_the_one_secure_endpoint() {

        final MultivaluedMap<String, String> body = new MultivaluedHashMap<>();

        // Given
        body.add("username", "user");
        body.add("password", "password");

        // When
        final Response login = client1.target(baseUrl).path("one").path("login").request().post(form(body));
        final Response secure1 = client1.target(baseUrl).path("one").path("secure").request().get();
        final Response secure2 = client1.target(baseUrl).path("two").path("secure").request().get();
        final Response secure3 = client1.target(baseUrl).path("secure").request().get();

        // Then
        assertThat(login.getStatus(), is(OK.getStatusCode()));
        assertThat(secure1.getStatus(), is(OK.getStatusCode()));
        assertThat(secure1.readEntity(String.class), is("one secure"));
        assertThat(secure2.getStatus(), is(OK.getStatusCode()));
        assertThat(secure2.readEntity(String.class), is("two secure"));
        assertThat(secure3.getStatus(), is(OK.getStatusCode()));
        assertThat(secure3.readEntity(String.class), is("secure"));
    }

    @Test
    public void Can_login_and_access_the_two_secure_endpoint() {

        final MultivaluedMap<String, String> body = new MultivaluedHashMap<>();

        // Given
        body.add("username", "user");
        body.add("password", "password");

        // When
        final Response login = client2.target(baseUrl).path("two").path("login").request().post(form(body));
        final Response secure1 = client2.target(baseUrl).path("one").path("secure").request().get();
        final Response secure2 = client2.target(baseUrl).path("two").path("secure").request().get();
        final Response secure3 = client2.target(baseUrl).path("secure").request().get();

        // Then
        assertThat(login.getStatus(), is(OK.getStatusCode()));
        assertThat(secure1.getStatus(), is(OK.getStatusCode()));
        assertThat(secure1.readEntity(String.class), is("one secure"));
        assertThat(secure2.getStatus(), is(OK.getStatusCode()));
        assertThat(secure2.readEntity(String.class), is("two secure"));
        assertThat(secure3.getStatus(), is(OK.getStatusCode()));
        assertThat(secure3.readEntity(String.class), is("secure"));
    }

    @Test
    public void Can_login_and_access_the_secure_endpoint() {

        final MultivaluedMap<String, String> body = new MultivaluedHashMap<>();

        // Given
        body.add("username", "user");
        body.add("password", "password");

        // When
        final Response login = client3.target(baseUrl).path("login").request().post(form(body));
        final Response secure1 = client3.target(baseUrl).path("one").path("secure").request().get();
        final Response secure2 = client3.target(baseUrl).path("two").path("secure").request().get();
        final Response secure3 = client3.target(baseUrl).path("secure").request().get();

        // Then
        assertThat(login.getStatus(), is(OK.getStatusCode()));
        assertThat(secure1.getStatus(), is(OK.getStatusCode()));
        assertThat(secure1.readEntity(String.class), is("one secure"));
        assertThat(secure2.getStatus(), is(OK.getStatusCode()));
        assertThat(secure2.readEntity(String.class), is("two secure"));
        assertThat(secure3.getStatus(), is(OK.getStatusCode()));
        assertThat(secure3.readEntity(String.class), is("secure"));
    }
}
