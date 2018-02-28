package com.lhauspie.example.controller;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping(value = "/customers", produces = MediaType.APPLICATION_JSON_VALUE)
public class CustomerApiController {

  private static final Logger log = LoggerFactory.getLogger(CustomerApiController.class);

  @GetMapping
  public List<String> getCustomers(Principal principal) {
    // This is how we can retrieve custom claims from the JWT
    if (principal instanceof KeycloakAuthenticationToken) {
      KeycloakPrincipal kp = (KeycloakPrincipal) ((KeycloakAuthenticationToken) principal).getPrincipal();
      IDToken token = kp.getKeycloakSecurityContext().getToken();

      Map<String, Object> otherClaims = token.getOtherClaims();
      log.info("otherClaims is {}", otherClaims);
    }
    return Arrays.asList("Scott Rossillo", "Kyung Lee", "Keith Leggins", "Ben Loy");
  }
}
