# METADATA
# description: Policy for listing application credentials
package identity.user.application_credential.list

default allow := false

allow if { input.credentials.is_admin }

allow if {
    "reader" in input.credentials.roles
    input.credentials.system == "all"
}

allow if { input.credentials.user_id == input.target.application_credential.user_id }

violation contains {"field": "user_id", "msg": "listing application credentials of a different user is not allowed."} if {
    not input.credentials.is_admin
    not input.credentials.system == "all"
    input.credentials.user_id != input.target.application_credential.user_id
}