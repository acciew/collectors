package kctest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Seeding a realm worth testing against.

// Fixture names the ids a test needs to look things up afterwards.
type Fixture struct {
	AliceID       string
	CarolID       string
	SvcClientUUID string
}

// seed builds the shape the collector has to get right: a person in a
// subgroup of a group that holds a role, a composite role, a client with a
// role and a service account, and a second person with a direct client role.
func SeedProbeRealm(t *testing.T, base string) Fixture {
	t.Helper()
	k := &Seeder{t: t, ctx: t.Context(), base: base, http: &http.Client{Timeout: 30 * time.Second}}
	k.login()

	k.post("/admin/realms", map[string]any{"realm": "probe", "enabled": true})
	k.post("/admin/realms/probe/clients", map[string]any{
		"clientId": "acciew", "secret": "s3cr3t", "publicClient": false,
		"serviceAccountsEnabled": true, "standardFlowEnabled": false,
	})
	k.grantRealmManagement("acciew")

	k.post("/admin/realms/probe/clients", map[string]any{
		"clientId": "app", "secret": "apps3cr3t", "publicClient": false,
		"serviceAccountsEnabled": true, "standardFlowEnabled": false,
	})
	svcUUID := k.clientUUID("app")
	k.post("/admin/realms/probe/clients/"+svcUUID+"/roles", map[string]any{"name": "app-writer"})

	for _, r := range []string{"r-child", "r-parent", "r-group"} {
		k.post("/admin/realms/probe/roles", map[string]any{"name": r})
	}
	child := k.getRaw("/admin/realms/probe/roles/r-child")
	parentID := k.roleID("r-parent")
	k.postRaw("/admin/realms/probe/roles-by-id/"+parentID+"/composites", "["+child+"]")

	k.post("/admin/realms/probe/groups", map[string]any{"name": "G"})
	gid := k.groupID("G")
	k.post("/admin/realms/probe/groups/"+gid+"/children", map[string]any{"name": "S"})
	sid := k.childID(gid, "S")
	groupRole := k.getRaw("/admin/realms/probe/roles/r-group")
	k.postRaw("/admin/realms/probe/groups/"+gid+"/role-mappings/realm", "["+groupRole+"]")

	k.post("/admin/realms/probe/users", map[string]any{
		"username": "alice", "enabled": true, "emailVerified": true,
		"firstName": "A", "lastName": "Lice",
	})
	aliceID := k.userID("alice")
	k.put("/admin/realms/probe/users/"+aliceID+"/groups/"+sid, nil)
	parentRole := k.getRaw("/admin/realms/probe/roles/r-parent")
	k.postRaw("/admin/realms/probe/users/"+aliceID+"/role-mappings/realm", "["+parentRole+"]")

	k.post("/admin/realms/probe/users", map[string]any{
		"username": "carol", "enabled": true, "emailVerified": true,
		"firstName": "C", "lastName": "Arol",
	})
	carolID := k.userID("carol")
	appRole := k.getRaw("/admin/realms/probe/clients/" + svcUUID + "/roles/app-writer")
	k.postRaw("/admin/realms/probe/users/"+carolID+"/role-mappings/clients/"+svcUUID, "["+appRole+"]")

	return Fixture{AliceID: aliceID, CarolID: carolID, SvcClientUUID: svcUUID}
}

// Seeder drives the Admin API as the bootstrap admin.
type Seeder struct {
	t     *testing.T
	ctx   context.Context
	base  string
	http  *http.Client
	token string
}

func (k *Seeder) login() {
	form := url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {AdminUser}, "password": {AdminPass},
	}
	req, err := http.NewRequestWithContext(k.ctx, http.MethodPost,
		k.base+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		k.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.http.Do(req)
	if err != nil {
		k.t.Fatalf("admin login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		k.t.Fatalf("admin login: %v", err)
	}
	k.token = body.AccessToken
}

func (k *Seeder) do(method, path, body string) string {
	k.t.Helper()
	req, err := http.NewRequestWithContext(k.ctx, method, k.base+path, strings.NewReader(body))
	if err != nil {
		k.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.http.Do(req)
	if err != nil {
		k.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	buf := new(strings.Builder)
	if _, err := io.Copy(buf, resp.Body); err != nil {
		k.t.Fatalf("%s %s: reading the response: %v", method, path, err)
	}
	// Conflict means the fixture already exists, which happens when a test
	// reruns against a container that outlived it. Not a failure.
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusConflict {
		k.t.Fatalf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, buf.String())
	}
	return buf.String()
}

func (k *Seeder) post(path string, body map[string]any) {
	k.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		k.t.Fatal(err)
	}
	k.do(http.MethodPost, path, string(raw))
}

func (k *Seeder) postRaw(path, body string) { k.t.Helper(); k.do(http.MethodPost, path, body) }

func (k *Seeder) put(path string, body map[string]any) {
	k.t.Helper()
	raw := "{}"
	if body != nil {
		b, _ := json.Marshal(body)
		raw = string(b)
	}
	k.do(http.MethodPut, path, raw)
}

func (k *Seeder) getRaw(path string) string {
	k.t.Helper()
	return k.do(http.MethodGet, path, "")
}

func (k *Seeder) list(path string) []map[string]any {
	k.t.Helper()
	var out []map[string]any
	if err := json.Unmarshal([]byte(k.getRaw(path)), &out); err != nil {
		k.t.Fatalf("%s: %v", path, err)
	}
	return out
}

func (k *Seeder) findID(path, field, value string) string {
	k.t.Helper()
	for _, item := range k.list(path) {
		if item[field] != value {
			continue
		}
		id, ok := item["id"].(string)
		if !ok {
			k.t.Fatalf("%s: the match has no string id: %v", path, item)
		}
		return id
	}
	k.t.Fatalf("%s: nothing with %s=%q", path, field, value)
	return ""
}

func (k *Seeder) clientUUID(clientID string) string {
	return k.findID("/admin/realms/probe/clients?clientId="+clientID, "clientId", clientID)
}
func (k *Seeder) roleID(name string) string {
	return k.findID("/admin/realms/probe/roles", "name", name)
}
func (k *Seeder) groupID(name string) string {
	return k.findID("/admin/realms/probe/groups", "name", name)
}
func (k *Seeder) childID(parent, name string) string {
	return k.findID("/admin/realms/probe/groups/"+parent+"/children", "name", name)
}
func (k *Seeder) userID(username string) string {
	return k.findID("/admin/realms/probe/users?username="+username, "username", username)
}

// grantRealmManagement gives the collector's service account the roles it
// needs to read a realm. An operator setting this up for real does the same
// thing, so getting it wrong here means the documentation is wrong too.
func (k *Seeder) grantRealmManagement(clientID string) {
	k.t.Helper()
	// The minimal set, measured against Keycloak 26.4.7 by granting each role
	// alone and recording which endpoints answered: view-clients gates
	// /clients, view-realm gates /roles-by-id/{id}/composites, view-events
	// gates /events/config, and view-users gates everything about users and
	// groups beyond the bare listing. query-users and query-groups answer the
	// listings and nothing else, which is what makes them dangerous rather
	// than merely redundant — see SetRealmManagement.
	k.SetRealmManagement(clientID, "view-users", "view-clients", "view-realm", "view-events")
}

// SetRealmManagement replaces the realm-management roles held by a client's
// service account, so a test can ask what a differently granted token sees.
func (k *Seeder) SetRealmManagement(clientID string, roles ...string) {
	k.t.Helper()
	uuid := k.clientUUID(clientID)
	body := k.do(http.MethodGet,
		"/admin/realms/probe/clients/"+uuid+"/service-account-user", "")
	var sa struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &sa); err != nil {
		k.t.Fatal(err)
	}
	rm := k.clientUUID("realm-management")
	held := k.getRaw("/admin/realms/probe/users/" + sa.ID + "/role-mappings/clients/" + rm)
	if held != "" && held != "[]" {
		k.do(http.MethodDelete,
			"/admin/realms/probe/users/"+sa.ID+"/role-mappings/clients/"+rm, held)
	}
	wanted := map[string]bool{}
	for _, r := range roles {
		wanted[r] = true
	}
	var grant []map[string]any
	for _, role := range k.list("/admin/realms/probe/clients/" + rm + "/roles") {
		if name, _ := role["name"].(string); wanted[name] {
			grant = append(grant, role)
			delete(wanted, name)
		}
	}
	// A misspelled role would otherwise be granted silently as nothing, and
	// the test that asked for it would pass for the wrong reason.
	for name := range wanted {
		k.t.Fatalf("realm-management has no role %q to grant", name)
	}
	raw, _ := json.Marshal(grant)
	k.postRaw("/admin/realms/probe/users/"+sa.ID+"/role-mappings/clients/"+rm, string(raw))
}

// Regrant opens a seeded Keycloak again so a test can change what the
// collector's token holds.
func Regrant(t *testing.T, base string, roles ...string) {
	t.Helper()
	// Not t.Context(): this is called from t.Cleanup too, and by then the
	// test's own context is already cancelled.
	k := &Seeder{t: t, ctx: context.Background(), base: base,
		http: &http.Client{Timeout: 30 * time.Second}}
	k.login()
	k.SetRealmManagement("acciew", roles...)
}
