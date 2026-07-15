# METADATA
# description: Policy for creating application credentials
package identity.user.application_credential.create

default allow := false

allow if {
    input.credentials.user_id == input.target.application_credential.user_id
}

violation contains {"field": "user_id", "msg": "creating application credentials for a different user is not allowed."} if {
    input.credentials.user_id != input.target.application_credential.user_id
}