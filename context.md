# Token rework Context

- when user authenticates through /v3/auth/tokens a SecurityContext is
  constructed from the authentication information. This context is passed
  together with ScopeInfo into `TokenApi::issue_token`. It returns a Token
  object that is then used to construct the fernet token and also return
  expanded information.
- The payload types used within Token enum are incorporating a lot of Optional
  fields only to use them as ExpandedToken. They are not necessary for the serde
  roundtrip.
- when user passes a fernet token to the regular api call the
  ValidatedSecurityContext is constructed from such token by calling
  `authenticate_by_token` and expanding role assignments into the
  ValidatedSecurityContext
- the GET /v3/auth/tokens call takes 2 tokens: x-auth-token of the service
  validating the user token. It is processed as a regular
  ValidatedSecurityContext. The x-subject-header token need to be validated and
  expanded to return it's details.
- The `Token` structure should not itself contain expanded information and be
  strictly responsible for fernet serialization/deserialization.
- In future the JWT token would need to be added undelining necessity to split
  `Token` from `ExpandedToken`
- the `issue_token` call accept ScopeInfo containing nearly all necessary
  information for the ExpandedToken
- maybe it is more reasonable to construct api Token response directly from
  SecurityContext instead of trying have an intermediate ExpandedToken structure
  as a interface to FernetToken and in future JwtToken
