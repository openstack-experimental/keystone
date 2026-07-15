# METADATA
# description: Policy for showing application credential details
package identity.user.application_credential.show

default allow := false

allow if { input.credentials.is_admin }

allow if {
    "reader" in input.credentials.roles
    input.credentials.system == "all"
}

allow if { input.credentials.user_id == input.target.application_credential.user_id }

violation contains {"field": "user_id", "msg": "viewing application credentials of a different user is not allowed."} if {
    not input.credentials.is_admin
    not input.credentials.system == "all"
    input.credentials.user_id != input.target.application_credential.user_id
}