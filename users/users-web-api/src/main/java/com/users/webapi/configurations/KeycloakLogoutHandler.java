package com.users.webapi.configurations;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@Slf4j
public class KeycloakLogoutHandler //implements LogoutHandler
{
//    private  RestTemplate restTemplate = new RestTemplate();
//
//    @Override
//    public void logout(HttpServletRequest request, HttpServletResponse response,
//                       Authentication auth) {
//        logoutFromKeycloak((OidcUser) auth.getPrincipal());
//    }
//
//    private void logoutFromKeycloak(OidcUser user) {
//        /**
//         * Tworzy URL do endpointu wylogowania Keycloak,
//         * korzystając z informacji o wystawcy tokena (issuer),
//         * który jest pobrany z OidcUser.
//         */
//        String endSessionEndpoint = user.getIssuer() + "/protocol/openid-connect/logout";
//        /**
//         * Używa UriComponentsBuilder do skonstruowania URL z parametrem zapytania id_token_hint,
//         * który jest wymagany przez Keycloak do procesu wylogowania
//         */
//        UriComponentsBuilder builder = UriComponentsBuilder
//                .fromUriString(endSessionEndpoint)
//                .queryParam("id_token_hint", user.getIdToken().getTokenValue());
//
//        ResponseEntity<String> logoutResponse = restTemplate.getForEntity(
//                builder.toUriString(), String.class);
//        if (logoutResponse.getStatusCode().is2xxSuccessful()) {
//            log.info("Successfulley logged out from Keycloak");
//        } else {
//            log.info("Could not propagate logout to Keycloak");
//        }
//    }
}

