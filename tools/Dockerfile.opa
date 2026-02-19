FROM docker.io/openpolicyagent/opa:1.13.2
# This preserves your entire hierarchy
COPY /policy /policy
