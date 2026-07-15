# METADATA
# description: Policy for deleting application credentials
package identity.user.application_credential.delete

default allow := false

allow if { input.credentials.is_admin }

allow if { input.credentials.user_id == input.target.application_credential.user_id }

violation contains {"field": "user_id", "msg": "deleting application credentials of a different user is not allowed."} if {
    not input.credentials.is_admin
    input.credentials.user_id != input.target.application_credential.user_id
}