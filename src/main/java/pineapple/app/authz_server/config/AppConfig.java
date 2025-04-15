package pineapple.app.authz_server.config;

import com.fasterxml.jackson.core.PrettyPrinter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class AppConfig {

  @Bean
  public UserDetailsService userDetailsService() {
    final var testUser = User.withUsername("user").password("{noop}pass").roles("USER").build();

    return new InMemoryUserDetailsManager(testUser);
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient client =
        RegisteredClient.withId("123")
            .clientId("pineapple-client")
            .clientSecret("{noop}pineapple")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8081")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.EMAIL)
            .scope(OidcScopes.PROFILE)
            .tokenSettings(
                TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1)).build())
            .clientSettings(
                ClientSettings.builder()
                    .requireProofKey(false)
                    .requireAuthorizationConsent(true)
                    .build())
            .build();

    return new InMemoryRegisteredClientRepository(client);
  }

  @Bean
  public AuthorizationServerSettings authzServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  @Bean
  OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
    return context -> {
      if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
        context
            .getClaims()
            .claims(
                claims -> {
                  claims.put("abc", "def");
                });
      }
    };
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();

    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

    RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID("123").build();

    return new ImmutableJWKSet<>(new JWKSet(rsaKey));
  }
}