package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// One GraphQL query, for the one question REST cannot answer.
//
// GitHub's REST team-members endpoint is transitive: it includes the members
// of child teams. Emitted as membership that turns an inherited route into a
// stated one, and tells a reviewer to remove somebody from a team they are
// not in. Subtracting the descendants does not fix it either, because
// somebody can be in both a parent and a child directly and would be
// subtracted out of the parent they really are in.
//
// GraphQL can be asked for immediate membership directly. It is worth one
// hand-written query and no library: the query is fixed, the response shape
// is small, and the alternative is a wrong answer.

// immediateMembersQuery asks for each team's own members. Aliased per team so
// one round trip answers for a batch.
const teamMembersBatch = 25

// ImmediateTeamMembers returns each team's own members, excluding the members
// of its child teams.
//
// The batch is deliberately modest: a query that asks for too much at once is
// one GitHub rejects wholesale, and a rejected batch answers for no team
// rather than for some.
func (c *Client) ImmediateTeamMembers(ctx context.Context, org string,
	slugs []string) (map[string][]User, error) {
	out := map[string][]User{}
	for start := 0; start < len(slugs); start += teamMembersBatch {
		end := min(start+teamMembersBatch, len(slugs))
		batch, err := c.immediateBatch(ctx, org, slugs[start:end])
		if err != nil {
			return nil, err
		}
		for slug, members := range batch {
			out[slug] = members
		}
	}
	return out, nil
}

func (c *Client) immediateBatch(ctx context.Context, org string,
	slugs []string) (map[string][]User, error) {
	var query strings.Builder
	query.WriteString(`query($org:String!){organization(login:$org){`)
	alias := make(map[string]string, len(slugs))
	for i, slug := range slugs {
		a := fmt.Sprintf("t%d", i)
		alias[a] = slug
		// membership: IMMEDIATE is the whole point of this call.
		fmt.Fprintf(&query, `%s:team(slug:%q){members(first:100,membership:IMMEDIATE)`+
			`{pageInfo{hasNextPage}nodes{login databaseId}}}`, a, slug)
	}
	query.WriteString("}}")

	body, err := json.Marshal(map[string]any{
		"query":     query.String(),
		"variables": map[string]string{"org": org},
	})
	if err != nil {
		return nil, &Error{Kind: Source, What: "asking for immediate team membership", Err: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.graphQLURL(), bytes.NewReader(body))
	if err != nil {
		return nil, &Error{Kind: Source, What: "asking for immediate team membership", Err: err}
	}
	c.sign(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &Error{Kind: Unavailable, What: "asking for immediate team membership", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return nil, errorFor(resp, "asking for immediate team membership")
	}

	var payload struct {
		Data struct {
			// A pointer, deliberately. GraphQL answers 200 with a null
			// team for one it cannot resolve — a secret team, a slug that
			// has moved — and decoding null into a value type creates the
			// key with no members. The caller would then see a team that
			// answered with nobody in it rather than a team that did not
			// answer, skip the fallback, and lose every membership edge for
			// it from a stream reporting itself complete.
			Organization map[string]*struct {
				Members struct {
					PageInfo struct {
						HasNextPage bool `json:"hasNextPage"`
					} `json:"pageInfo"`
					Nodes []struct {
						Login      string `json:"login"`
						DatabaseID int64  `json:"databaseId"`
					} `json:"nodes"`
				} `json:"members"`
			} `json:"organization"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, &Error{Kind: Source, What: "asking for immediate team membership",
			Err: fmt.Errorf("unreadable response: %w", err)}
	}
	// GraphQL answers 200 with an errors array. A partial answer here would
	// be a partial membership list, which is worse than no answer: it would
	// silently drop somebody's access.
	if len(payload.Errors) > 0 {
		return nil, &Error{Kind: Source, What: "asking for immediate team membership",
			Message: payload.Errors[0].Message}
	}

	out := map[string][]User{}
	for a, team := range payload.Data.Organization {
		slug, ok := alias[a]
		if !ok || team == nil {
			continue
		}
		if team.Members.PageInfo.HasNextPage {
			return nil, &Error{Kind: Source, What: "asking for immediate team membership",
				Err: fmt.Errorf("team %s has more than 100 immediate members and this "+
					"collector does not page them yet; a partial membership list would "+
					"silently drop somebody's access", slug)}
		}
		members := make([]User, 0, len(team.Members.Nodes))
		for _, n := range team.Members.Nodes {
			members = append(members, User{Login: n.Login, ID: n.DatabaseID, Type: "User"})
		}
		out[slug] = members
	}
	return out, nil
}

// graphQLURL is the GraphQL endpoint beside this installation's REST API.
func (c *Client) graphQLURL() string {
	if base, ok := strings.CutSuffix(c.base, "/api/v3"); ok {
		return base + "/api/graphql"
	}
	if c.base == "https://api.github.com" {
		return "https://api.github.com/graphql"
	}
	return c.base + "/graphql"
}

// GraphQLURLFor exposes the endpoint a client would use, so a test can check
// that an Enterprise Server installation is derived correctly without making
// a request to a host that does not exist.
func GraphQLURLFor(c *Client) string { return c.graphQLURL() }
