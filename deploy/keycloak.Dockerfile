# Keycloak built ahead of time so the runtime container needs no writable augmentation.
FROM quay.io/keycloak/keycloak:26.3.3@sha256:6a7217a100bd3e5de4063a27a538ef999a3c5a88c4b4ec0ffc0a642aee7b2597 AS builder
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=false
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.3.3@sha256:6a7217a100bd3e5de4063a27a538ef999a3c5a88c4b4ec0ffc0a642aee7b2597
COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY deploy/keycloak-entrypoint.sh /opt/absensi/keycloak-entrypoint.sh
COPY deploy/keycloak-realm-bootstrap.sh /opt/absensi/keycloak-realm-bootstrap.sh
USER 1000:0
ENTRYPOINT ["/bin/bash", "/opt/absensi/keycloak-entrypoint.sh"]
