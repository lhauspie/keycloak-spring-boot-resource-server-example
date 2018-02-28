package com.lhauspie.example.config;

import org.keycloak.adapters.springsecurity.account.KeycloakRole;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Performs authentication on a {@link KeycloakAuthenticationToken}.
 *
 * @author Logan HAUSPIE
 */
public class MyKeycloakAuthenticationProvider implements AuthenticationProvider {
  private GrantedAuthoritiesMapper grantedAuthoritiesMapper;

  public void setGrantedAuthoritiesMapper(GrantedAuthoritiesMapper grantedAuthoritiesMapper) {
    this.grantedAuthoritiesMapper = grantedAuthoritiesMapper;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) authentication;
    List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();

    // Extract roles from the `realm_access.roles`
    Set<String> roles = token.getAccount().getRoles();
    if (roles != null) {
      grantedAuthorities.addAll(
          roles.stream().map(
              role -> new KeycloakRole(role)
          ).collect(Collectors.toList())
      );
    }

    // Extract roles from the `resource_access.<client-id>.roles`
    Map<String, AccessToken.Access> resourceAccess = token.getAccount().getKeycloakSecurityContext().getToken().getResourceAccess();
    if (resourceAccess != null) {
      grantedAuthorities.addAll(
          resourceAccess.entrySet().stream().flatMap(
              access -> access.getValue().getRoles().stream().map(
                  role -> access.getKey() + "/" + role
              )
          ).map(
              role -> new KeycloakRole(role)
          ).collect(Collectors.toList())
      );
    }

    return new KeycloakAuthenticationToken(token.getAccount(), token.isInteractive(), mapAuthorities(grantedAuthorities));
  }

  private Collection<? extends GrantedAuthority> mapAuthorities(
      Collection<? extends GrantedAuthority> authorities) {
    return grantedAuthoritiesMapper != null
        ? grantedAuthoritiesMapper.mapAuthorities(authorities)
        : authorities;
  }

  @Override
  public boolean supports(Class<?> aClass) {
    return KeycloakAuthenticationToken.class.isAssignableFrom(aClass);
  }
}
