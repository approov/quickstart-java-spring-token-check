package com.criticalblue.approov.jwt;

import com.criticalblue.approov.jwt.authentication.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static ApproovConfig approovConfig = ApproovConfig.getInstance();

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5000"));
        configuration.setAllowedMethods(Arrays.asList("GET"));
        configuration.addAllowedHeader("Authorization");
        configuration.addAllowedHeader("Approov-Token");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/error");
    }

    @Configuration
    @Order(1)
    public static class ApproovWebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.cors();

            http
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                .csrf().disable()
                .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            http
                .securityContext()
                .securityContextRepository(new ApproovSecurityContextRepository(approovConfig, false))
                .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(new ApproovAuthenticationEntryPoint())
                .and()
                    .antMatcher("/shapes")
                        .authorizeRequests()
                        .antMatchers(HttpMethod.GET, "/shapes").authenticated();
        }
    }

    @Configuration
    @Order(2)
    public static class AproovPayloadWebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.cors();

            http
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                .csrf().disable()
                .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            http
                .securityContext()
                .securityContextRepository(new ApproovSecurityContextRepository(approovConfig, true))
                .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(new ApproovAuthenticationEntryPoint())
                .and()
                    .antMatcher("/forms")
                        .authorizeRequests()
                        .antMatchers(HttpMethod.GET, "/forms").authenticated();
        }
    }

    @Configuration
    @Order(3)
    public static class ApiWebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.cors();

            http
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                .csrf().disable()
                .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            http
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/**").permitAll();
        }
    }
}
