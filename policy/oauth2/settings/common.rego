# METADATA
# description: Shared predicates for OAuth2 per-domain settings policies (ADR 0043 §1)
package identity.oauth2.settings

mode_rank := {"disabled": 0, "optional": 1, "required": 2}

settings_domain_id := input.existing.oauth2_settings.domain_id

own_domain if {
	settings_domain_id != null
	settings_domain_id == input.credentials.domain_id
}

foreign_domain if {
	settings_domain_id != null
	settings_domain_id != input.credentials.domain_id
}

# The update lowers the stored DPoP mode of the domain.
dpop_lowered if {
	mode_rank[input.target.oauth2_settings.dpop] < mode_rank[input.existing.oauth2_settings.dpop]
}

# The update sets a DPoP mode below the global one. The global value is a
# floor, so the stored value only matters when it is stricter; a request that
# leaves the stored value unchanged is not such a setting.
dpop_below_global if {
	mode_rank[input.target.oauth2_settings.dpop] < mode_rank[input.target.oauth2_settings.global_dpop]
	input.target.oauth2_settings.dpop != input.existing.oauth2_settings.dpop
}
