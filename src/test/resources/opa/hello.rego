# METADATA
# title: zylos-service-hello fine-grained authorization
# description: >-
#   Resource-level decision for hello. Placeholder substrate to prove the
#   centralized-OPA decision path end to end; real ownership policy lands in Catalog.
# entrypoint: true
package zylos.authz.hello

import data.zylos.authz.common
import rego.v1

# Queried by the service at: data.zylos.authz.hello.decision
decision := {
	"allow": allow,
	"reasons": reasons,
	"obligations": {},
}

default allow := false

allow if {
	input.action == "greeting:read"
	authorized_role
}

authorized_role if common.has_role("customer")

authorized_role if common.has_role("admin")

reasons := ["subject holds an authorized role for greeting:read"] if allow

reasons := ["no matching authorization rule"] if not allow
