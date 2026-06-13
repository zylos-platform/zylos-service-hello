# METADATA
# title: Common authorization helpers
# description: Claim-extraction helpers shared across all Zylos service policies.
package zylos.authz.common

import rego.v1

# True if the subject carries the given realm role. Undefined-safe.
has_role(role) if {
	role in input.subject.roles
}
