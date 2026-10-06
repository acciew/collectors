# Keycloak collector

Collects realms, users, groups, realm and client roles, composite roles and
role mappings from Keycloak over its Admin REST API, and resolves effective
access: a grant reached through a group, a subgroup or a composite role is
reported as `EFFECTIVE` with the route it came by. It never writes.

```sh
cat > keycloak.json <<'EOF'
{
  "base_url": "https://sso.example.com",
  "auth_realm": "master",
  "client_id": "acciew-reader",
  "client_secret": "env:KC_SECRET",
  "realms": ["corp"]
}
EOF
export KC_SECRET=...
```

The Acciew host runs the collector with this configuration: a check first, then
a collection. `realms` empty means every realm the credentials reach.
`client_secret` is a reference (`env:NAME` or `file:/path`), never a literal.

## Permissions

The collector authenticates as one service account of a confidential client in
`auth_realm`, and in every realm it reads that account needs these roles from
the realm's management client (`realm-management`, or `<realm>-realm` when read
through the master realm):

| Role | Needed to |
|---|---|
| `view-users` | list users, groups, group members, and the roles users and groups hold |
| `view-clients` | list clients, their roles, and their service accounts |
| `view-realm` | list realm roles, resolve composite roles, and read whether the realm is enabled |
| `view-events` | read login events, for last activity. Optional |

A `manage-*` role is accepted in place of the matching `view-*` role. The
`query-*` roles are not enough: Keycloak answers a token that holds only those
with a shorter list instead of refusing, and a collection that looks whole but
is not is the failure this collector exists to avoid. The check says which role
is missing, and a collection fails rather than reporting a partial population
as whole.

The collector also fails when it cannot tell what its token may read: if
lightweight access tokens are on for the client, or the `roles` client scope has
been removed from it, Keycloak leaves the roles out of the token. The error says
how to fix it.

## Activity

Last activity comes from Keycloak's login events, declared as two signals:
`login_event` (Keycloak's `LOGIN`) for people and `client_login_event`
(`CLIENT_LOGIN`) for service accounts, which authenticate by client credentials
and never emit the first.

- **Event storage is off** (Keycloak's default): the realm is reported once as
  recording no activity. People are not marked inactive.
- **The events read is refused:** the realm is reported as "could not find out",
  which points at a credential, not at a setting.
- **Events are on:** each person is `seen` with a date, or `not seen` in a
  window that starts at the oldest event of that type the collector read, the
  only lower bound that can be proved, and ends now. The window is short on a realm whose log is
  new or has been trimmed, and shorter still on a very active one, because the
  collector reads one page of at most 5,000 events, shared by both signals. With no events of a signal at
  all there is no window to claim, and the realm reports no answer for it. Not
  seen never means never.

## What it does not collect

Keycloak organizations, identity providers, client scopes, authentication flows,
user credentials, sessions and tokens.

## What has not been verified

Tested against Keycloak 26.4.7. Other versions are not tested. The Admin REST API
is stable in practice but not contractually.
