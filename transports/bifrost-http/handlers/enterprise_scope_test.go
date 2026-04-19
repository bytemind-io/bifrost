package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/valyala/fasthttp"
	enterprise "github.com/workpieces/bifrost/plugins/enterprise"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type enterpriseHandlerTestHarness struct {
	handler   *EnterpriseHandler
	userStore *enterprise.UserStore
	audit     *enterprise.AuditStore
}

func newEnterpriseHandlerTestHarness(t *testing.T) *enterpriseHandlerTestHarness {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}

	userStore, err := enterprise.NewUserStore(db)
	if err != nil {
		t.Fatalf("failed to create user store: %v", err)
	}
	roleStore, err := enterprise.NewRoleStore(db)
	if err != nil {
		t.Fatalf("failed to create role store: %v", err)
	}
	auditStore, err := enterprise.NewAuditStore(db)
	if err != nil {
		t.Fatalf("failed to create audit store: %v", err)
	}
	t.Cleanup(auditStore.Close)

	return &enterpriseHandlerTestHarness{
		handler:   NewEnterpriseHandler(userStore, auditStore, roleStore, nil),
		userStore: userStore,
		audit:     auditStore,
	}
}

func newEnterpriseRequestCtx(method, uri, body string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Init(&fasthttp.Request{}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, nil)
	ctx.Request.Header.SetMethod(method)
	ctx.Request.SetRequestURI(uri)
	if body != "" {
		ctx.Request.Header.SetContentType("application/json")
		ctx.Request.SetBodyString(body)
	}
	return ctx
}

func decodeUserResponse(t *testing.T, ctx *fasthttp.RequestCtx) enterprise.TableUser {
	t.Helper()

	var user enterprise.TableUser
	if err := json.Unmarshal(ctx.Response.Body(), &user); err != nil {
		t.Fatalf("failed to decode user response: %v body=%s", err, string(ctx.Response.Body()))
	}
	return user
}

func TestEnterpriseHandler_UpdateUser_NonAdminScopeAndSensitiveFields(t *testing.T) {
	h := newEnterpriseHandlerTestHarness(t)
	ctx := context.Background()

	teamA := "team-a"
	teamB := "team-b"
	actor, _ := h.userStore.CreateUser(ctx, "actor@test.com", "Actor", "pass12345", "Developer", &teamA)
	victim, _ := h.userStore.CreateUser(ctx, "victim@test.com", "Victim", "pass12345", "Viewer", &teamB)

	crossCtx := newEnterpriseRequestCtx(fasthttp.MethodPut, "/api/enterprise/users/"+victim.ID, `{"name":"Hacked"}`)
	crossCtx.SetUserValue("user_id", victim.ID)
	crossCtx.SetUserValue(enterprise.CtxKeyUserID, actor.ID)
	crossCtx.SetUserValue(enterprise.CtxKeyUserRole, actor.Role)
	crossCtx.SetUserValue(enterprise.CtxKeyUserTeamID, actor.TeamID)

	h.handler.updateUser(crossCtx)

	if crossCtx.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Fatalf("expected cross-team update to be forbidden, got %d: %s", crossCtx.Response.StatusCode(), string(crossCtx.Response.Body()))
	}

	selfCtx := newEnterpriseRequestCtx(fasthttp.MethodPut, "/api/enterprise/users/"+actor.ID, `{"name":"Updated Actor","role":"Admin","team_id":"team-b","is_active":false}`)
	selfCtx.SetUserValue("user_id", actor.ID)
	selfCtx.SetUserValue(enterprise.CtxKeyUserID, actor.ID)
	selfCtx.SetUserValue(enterprise.CtxKeyUserRole, actor.Role)
	selfCtx.SetUserValue(enterprise.CtxKeyUserTeamID, actor.TeamID)

	h.handler.updateUser(selfCtx)

	if selfCtx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected self update to succeed, got %d: %s", selfCtx.Response.StatusCode(), string(selfCtx.Response.Body()))
	}

	updated := decodeUserResponse(t, selfCtx)
	if updated.Name != "Updated Actor" {
		t.Fatalf("expected safe field update to persist, got name=%q", updated.Name)
	}
	if updated.Role != "Developer" {
		t.Fatalf("expected role to remain unchanged, got %q", updated.Role)
	}
	if updated.TeamID == nil || *updated.TeamID != teamA {
		t.Fatalf("expected team to remain %q, got %+v", teamA, updated.TeamID)
	}
	if !updated.IsActive {
		t.Fatal("expected is_active to remain unchanged")
	}
}

func TestEnterpriseHandler_GetUser_NonAdminCannotReadCrossTeamUser(t *testing.T) {
	h := newEnterpriseHandlerTestHarness(t)
	ctx := context.Background()

	teamA := "team-a"
	teamB := "team-b"
	actor, _ := h.userStore.CreateUser(ctx, "actor-read@test.com", "Actor", "pass12345", "Developer", &teamA)
	victim, _ := h.userStore.CreateUser(ctx, "victim-read@test.com", "Victim", "pass12345", "Viewer", &teamB)

	reqCtx := newEnterpriseRequestCtx(fasthttp.MethodGet, "/api/enterprise/users/"+victim.ID, "")
	reqCtx.SetUserValue("user_id", victim.ID)
	reqCtx.SetUserValue(enterprise.CtxKeyUserID, actor.ID)
	reqCtx.SetUserValue(enterprise.CtxKeyUserRole, actor.Role)
	reqCtx.SetUserValue(enterprise.CtxKeyUserTeamID, actor.TeamID)

	h.handler.getUser(reqCtx)

	if reqCtx.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Fatalf("expected cross-team read to be forbidden, got %d: %s", reqCtx.Response.StatusCode(), string(reqCtx.Response.Body()))
	}
}

func TestEnterpriseHandler_ListUsers_NonAdminIsScoped(t *testing.T) {
	h := newEnterpriseHandlerTestHarness(t)
	ctx := context.Background()

	teamA := "team-a"
	teamB := "team-b"
	actor, _ := h.userStore.CreateUser(ctx, "actor-list@test.com", "Actor", "pass12345", "Developer", &teamA)
	teammate, _ := h.userStore.CreateUser(ctx, "teammate-list@test.com", "Teammate", "pass12345", "Viewer", &teamA)
	_, _ = h.userStore.CreateUser(ctx, "outsider-list@test.com", "Outsider", "pass12345", "Viewer", &teamB)

	reqCtx := newEnterpriseRequestCtx(fasthttp.MethodGet, "/api/enterprise/users?limit=100", "")
	reqCtx.SetUserValue(enterprise.CtxKeyUserID, actor.ID)
	reqCtx.SetUserValue(enterprise.CtxKeyUserRole, actor.Role)
	reqCtx.SetUserValue(enterprise.CtxKeyUserTeamID, actor.TeamID)

	h.handler.listUsers(reqCtx)

	if reqCtx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected list users to succeed, got %d: %s", reqCtx.Response.StatusCode(), string(reqCtx.Response.Body()))
	}

	var response struct {
		Data []enterprise.TableUser `json:"data"`
	}
	if err := json.Unmarshal(reqCtx.Response.Body(), &response); err != nil {
		t.Fatalf("failed to decode list users response: %v body=%s", err, string(reqCtx.Response.Body()))
	}
	if len(response.Data) != 2 {
		t.Fatalf("expected exactly 2 in-scope users, got %d", len(response.Data))
	}
	seen := map[string]bool{}
	for _, user := range response.Data {
		seen[user.ID] = true
		if user.TeamID == nil || *user.TeamID != teamA {
			t.Fatalf("expected user %s to stay in team %q, got %+v", user.ID, teamA, user.TeamID)
		}
	}
	if !seen[actor.ID] || !seen[teammate.ID] {
		t.Fatalf("expected actor and teammate in response, got %+v", seen)
	}
}

func TestEnterpriseHandler_DeleteUser_NonAdminCannotDeleteCrossTeamUser(t *testing.T) {
	h := newEnterpriseHandlerTestHarness(t)
	ctx := context.Background()

	teamA := "team-a"
	teamB := "team-b"
	actor, _ := h.userStore.CreateUser(ctx, "actor-delete@test.com", "Actor", "pass12345", "Developer", &teamA)
	victim, _ := h.userStore.CreateUser(ctx, "victim-delete@test.com", "Victim", "pass12345", "Viewer", &teamB)

	reqCtx := newEnterpriseRequestCtx(fasthttp.MethodDelete, "/api/enterprise/users/"+victim.ID, "")
	reqCtx.SetUserValue("user_id", victim.ID)
	reqCtx.SetUserValue(enterprise.CtxKeyUserID, actor.ID)
	reqCtx.SetUserValue(enterprise.CtxKeyUserRole, actor.Role)
	reqCtx.SetUserValue(enterprise.CtxKeyUserTeamID, actor.TeamID)

	h.handler.deleteUser(reqCtx)

	if reqCtx.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Fatalf("expected cross-team delete to be forbidden, got %d: %s", reqCtx.Response.StatusCode(), string(reqCtx.Response.Body()))
	}
	if _, err := h.userStore.GetUser(ctx, victim.ID); err != nil {
		t.Fatalf("expected victim user to still exist, got err=%v", err)
	}
}

func TestEnterpriseHandler_ListTeamMembers_NonAdminScope(t *testing.T) {
	h := newEnterpriseHandlerTestHarness(t)
	ctx := context.Background()

	teamA := "team-a"
	teamB := "team-b"
	actor, _ := h.userStore.CreateUser(ctx, "actor-members@test.com", "Actor", "pass12345", "Developer", &teamA)
	_, _ = h.userStore.CreateUser(ctx, "member-a@test.com", "Member A", "pass12345", "Viewer", &teamA)
	_, _ = h.userStore.CreateUser(ctx, "member-b@test.com", "Member B", "pass12345", "Viewer", &teamB)

	reqCtx := newEnterpriseRequestCtx(fasthttp.MethodGet, "/api/enterprise/teams/"+teamB+"/members", "")
	reqCtx.SetUserValue("team_id", teamB)
	reqCtx.SetUserValue(enterprise.CtxKeyUserID, actor.ID)
	reqCtx.SetUserValue(enterprise.CtxKeyUserRole, actor.Role)
	reqCtx.SetUserValue(enterprise.CtxKeyUserTeamID, actor.TeamID)

	h.handler.listTeamMembers(reqCtx)

	if reqCtx.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Fatalf("expected cross-team members read to be forbidden, got %d: %s", reqCtx.Response.StatusCode(), string(reqCtx.Response.Body()))
	}
}

func TestEnterpriseHandler_AssignTeamMember_NonAdminScope(t *testing.T) {
	h := newEnterpriseHandlerTestHarness(t)
	ctx := context.Background()

	teamA := "team-a"
	teamB := "team-b"
	actor, _ := h.userStore.CreateUser(ctx, "actor-assign@test.com", "Actor", "pass12345", "Developer", &teamA)
	outsider, _ := h.userStore.CreateUser(ctx, "outsider-assign@test.com", "Outsider", "pass12345", "Viewer", &teamB)
	unassigned, _ := h.userStore.CreateUser(ctx, "unassigned-assign@test.com", "Unassigned", "pass12345", "Viewer", nil)

	otherTeamCtx := newEnterpriseRequestCtx(fasthttp.MethodPost, "/api/enterprise/teams/"+teamB+"/members", `{"user_id":"`+unassigned.ID+`"}`)
	otherTeamCtx.SetUserValue("team_id", teamB)
	otherTeamCtx.SetUserValue(enterprise.CtxKeyUserID, actor.ID)
	otherTeamCtx.SetUserValue(enterprise.CtxKeyUserRole, actor.Role)
	otherTeamCtx.SetUserValue(enterprise.CtxKeyUserTeamID, actor.TeamID)

	h.handler.assignTeamMember(otherTeamCtx)

	if otherTeamCtx.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Fatalf("expected assigning into another team to be forbidden, got %d: %s", otherTeamCtx.Response.StatusCode(), string(otherTeamCtx.Response.Body()))
	}

	crossUserCtx := newEnterpriseRequestCtx(fasthttp.MethodPost, "/api/enterprise/teams/"+teamA+"/members", `{"user_id":"`+outsider.ID+`"}`)
	crossUserCtx.SetUserValue("team_id", teamA)
	crossUserCtx.SetUserValue(enterprise.CtxKeyUserID, actor.ID)
	crossUserCtx.SetUserValue(enterprise.CtxKeyUserRole, actor.Role)
	crossUserCtx.SetUserValue(enterprise.CtxKeyUserTeamID, actor.TeamID)

	h.handler.assignTeamMember(crossUserCtx)

	if crossUserCtx.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Fatalf("expected stealing cross-team user to be forbidden, got %d: %s", crossUserCtx.Response.StatusCode(), string(crossUserCtx.Response.Body()))
	}

	ownTeamCtx := newEnterpriseRequestCtx(fasthttp.MethodPost, "/api/enterprise/teams/"+teamA+"/members", `{"user_id":"`+unassigned.ID+`"}`)
	ownTeamCtx.SetUserValue("team_id", teamA)
	ownTeamCtx.SetUserValue(enterprise.CtxKeyUserID, actor.ID)
	ownTeamCtx.SetUserValue(enterprise.CtxKeyUserRole, actor.Role)
	ownTeamCtx.SetUserValue(enterprise.CtxKeyUserTeamID, actor.TeamID)

	h.handler.assignTeamMember(ownTeamCtx)

	if ownTeamCtx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected assigning unassigned user into own team to succeed, got %d: %s", ownTeamCtx.Response.StatusCode(), string(ownTeamCtx.Response.Body()))
	}
	updated, err := h.userStore.GetUser(ctx, unassigned.ID)
	if err != nil {
		t.Fatalf("failed to reload unassigned user: %v", err)
	}
	if updated.TeamID == nil || *updated.TeamID != teamA {
		t.Fatalf("expected assigned user to join team %q, got %+v", teamA, updated.TeamID)
	}
}

func TestEnterpriseHandler_RemoveTeamMember_NonAdminScope(t *testing.T) {
	h := newEnterpriseHandlerTestHarness(t)
	ctx := context.Background()

	teamA := "team-a"
	teamB := "team-b"
	actor, _ := h.userStore.CreateUser(ctx, "actor-remove@test.com", "Actor", "pass12345", "Developer", &teamA)
	teammate, _ := h.userStore.CreateUser(ctx, "teammate-remove@test.com", "Teammate", "pass12345", "Viewer", &teamA)
	outsider, _ := h.userStore.CreateUser(ctx, "outsider-remove@test.com", "Outsider", "pass12345", "Viewer", &teamB)

	otherTeamCtx := newEnterpriseRequestCtx(fasthttp.MethodDelete, "/api/enterprise/teams/"+teamB+"/members/"+outsider.ID, "")
	otherTeamCtx.SetUserValue("team_id", teamB)
	otherTeamCtx.SetUserValue("user_id", outsider.ID)
	otherTeamCtx.SetUserValue(enterprise.CtxKeyUserID, actor.ID)
	otherTeamCtx.SetUserValue(enterprise.CtxKeyUserRole, actor.Role)
	otherTeamCtx.SetUserValue(enterprise.CtxKeyUserTeamID, actor.TeamID)

	h.handler.removeTeamMember(otherTeamCtx)

	if otherTeamCtx.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Fatalf("expected removing member from another team to be forbidden, got %d: %s", otherTeamCtx.Response.StatusCode(), string(otherTeamCtx.Response.Body()))
	}

	ownTeamCtx := newEnterpriseRequestCtx(fasthttp.MethodDelete, "/api/enterprise/teams/"+teamA+"/members/"+teammate.ID, "")
	ownTeamCtx.SetUserValue("team_id", teamA)
	ownTeamCtx.SetUserValue("user_id", teammate.ID)
	ownTeamCtx.SetUserValue(enterprise.CtxKeyUserID, actor.ID)
	ownTeamCtx.SetUserValue(enterprise.CtxKeyUserRole, actor.Role)
	ownTeamCtx.SetUserValue(enterprise.CtxKeyUserTeamID, actor.TeamID)

	h.handler.removeTeamMember(ownTeamCtx)

	if ownTeamCtx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected removing own team member to succeed, got %d: %s", ownTeamCtx.Response.StatusCode(), string(ownTeamCtx.Response.Body()))
	}
	updated, err := h.userStore.GetUser(ctx, teammate.ID)
	if err != nil {
		t.Fatalf("failed to reload teammate: %v", err)
	}
	if updated.TeamID != nil {
		t.Fatalf("expected removed teammate to have nil team_id, got %+v", updated.TeamID)
	}
}
