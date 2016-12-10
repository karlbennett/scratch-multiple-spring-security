package scratch.multiple.spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.Http401AuthenticationEntryPoint;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static javax.servlet.http.HttpServletResponse.SC_OK;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

/**
 * @author Karl Bennett
 */
@SpringBootApplication
@EnableWebMvc
@EnableWebSecurity
@RestController
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Configuration
    @Order(1)
    public static class Security1 extends WebSecurityConfigurerAdapter {

        private static final String ONE_LOGIN = "/one/login";

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable()
                .antMatcher("/one/**")
                .authorizeRequests()
                .antMatchers("/one/**").hasAuthority("ROLE_ONE")
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage(ONE_LOGIN).permitAll()
                .successHandler(new Http200SuccessHandler())
                .failureHandler(new Http401FailureHandler())
                .and()
                .exceptionHandling().authenticationEntryPoint(new Http401AuthenticationEntryPoint(ONE_LOGIN));
        }
    }

    @Configuration
    @Order(2)
    public static class Security2 extends WebSecurityConfigurerAdapter {

        private static final String TWO_LOGIN = "/two/login";

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable()
                .antMatcher("/two/**")
                .authorizeRequests()
                .antMatchers("/two/**").hasAuthority("ROLE_TWO")
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage(TWO_LOGIN).permitAll()
                .successHandler(new Http200SuccessHandler())
                .failureHandler(new Http401FailureHandler())
                .and()
                .exceptionHandling().authenticationEntryPoint(new Http401AuthenticationEntryPoint(TWO_LOGIN));
        }
    }

    @Configuration
    @Order(3)
    public static class Security3 extends WebSecurityConfigurerAdapter {

        private static final String LOGIN = "/login";

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable()
                .antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/**").hasAuthority("ROLE_THREE")
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage(LOGIN).permitAll()
                .successHandler(new Http200SuccessHandler())
                .failureHandler(new Http401FailureHandler())
                .and()
                .exceptionHandling().authenticationEntryPoint(new Http401AuthenticationEntryPoint(LOGIN));
        }
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user1").password("password").roles("ONE")
            .and().withUser("user2").password("password").roles("TWO")
            .and().withUser("user3").password("password").roles("THREE");
    }

    @RequestMapping(path = "/one/secure", method = GET, produces = TEXT_PLAIN_VALUE)
    public String oneSecure() {
        return "one secure";
    }

    @RequestMapping(path = "/two/secure", method = GET, produces = TEXT_PLAIN_VALUE)
    public String twoSecure() {
        return "two secure";
    }

    @RequestMapping(path = "/secure", method = GET, produces = TEXT_PLAIN_VALUE)
    public String secure() {
        return "secure";
    }

    private static class Http200SuccessHandler implements AuthenticationSuccessHandler {

        @Override
        public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
        ) throws IOException, ServletException {
            response.setStatus(SC_OK);
        }
    }

    private static class Http401FailureHandler implements AuthenticationFailureHandler {
        @Override
        public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
        ) throws IOException, ServletException {
            response.setStatus(SC_UNAUTHORIZED);
        }
    }
}
