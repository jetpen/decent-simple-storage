ARG KEYCLOAK_BASE
FROM ${KEYCLOAK_BASE}
COPY target/kc-wallet-grant-prototype-0.1.0-SNAPSHOT.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
