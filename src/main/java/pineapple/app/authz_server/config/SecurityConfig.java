package pineapple.app.authz_server.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class SecurityConfig {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {

    Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper =
        (context) -> {
          OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
          JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
          Map<String, Object> claims = new HashMap<>();
          claims.put("sub", principal.getName());
          claims.put("name", principal.getToken().getClaimAsString("name"));
          claims.put("given_name", principal.getToken().getClaimAsString("given_name"));
          claims.put("middle_name", principal.getToken().getClaimAsString("middle_name"));
          claims.put("family_name", principal.getToken().getClaimAsString("family_name"));
          claims.put("email", principal.getToken().getClaimAsString("email"));
          claims.put("gender", principal.getToken().getClaimAsString("gender"));

          claims.put("preferred_language", "English");
          claims.put("user_role", "admin");

          return new OidcUserInfo(claims);
        };
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
        OAuth2AuthorizationServerConfigurer.authorizationServer();
    http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
        .with(
            authorizationServerConfigurer,
            (authorizationServer) ->
                authorizationServer.oidc(
                    oidc ->
                        oidc.userInfoEndpoint(
                            (userInfo) -> userInfo.userInfoMapper(userInfoMapper))));

    //    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(withDefaults());
    http.exceptionHandling(
        e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
    return http.build();
  }

  @Bean
  @Order(Ordered.LOWEST_PRECEDENCE)
  public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
    http.formLogin(withDefaults()).authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    return http.build();
  }
}