#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:8080}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@bifrost.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
PASSWORD="${PASSWORD:-testpass123}"
NOW="$(date +%s%N)"
JSON_HEADER="Content-Type: application/json"

roles=()
users=()
teams=()
virtual_keys=()

post_json() {
	local path="$1"
	local cookie="$2"
	local data="$3"
	curl -sS -w '\n%{http_code}' -H "$JSON_HEADER" -H "Cookie: $cookie" -X POST "$BASE$path" --data "$data"
}

put_json() {
	local path="$1"
	local cookie="$2"
	local data="$3"
	curl -sS -w '\n%{http_code}' -H "$JSON_HEADER" -H "Cookie: $cookie" -X PUT "$BASE$path" --data "$data"
}

delete_req() {
	local path="$1"
	local cookie="$2"
	curl -sS -w '\n%{http_code}' -H "Cookie: $cookie" -X DELETE "$BASE$path"
}

get_req() {
	local path="$1"
	local cookie="$2"
	curl -sS -w '\n%{http_code}' -H "Cookie: $cookie" "$BASE$path"
}

body() {
	sed '$d' <<<"$1"
}

status() {
	tail -n1 <<<"$1"
}

login() {
	local email="$1"
	local password="$2"
	curl -sS -i -H "$JSON_HEADER" -X POST "$BASE/api/enterprise/login" \
		--data "{\"username\":\"$email\",\"password\":\"$password\"}" |
		tr -d '\r' |
		awk -F'[=;]' '/^Set-Cookie: token=/{print "token=" $2; exit}'
}

assert_status() {
	local label="$1"
	local got="$2"
	local want="$3"
	if [[ "$got" == "$want" ]]; then
		printf 'PASS %-42s expected=%s got=%s\n' "$label" "$want" "$got"
	else
		printf 'FAIL %-42s expected=%s got=%s\n' "$label" "$want" "$got"
		return 1
	fi
}

cleanup() {
	set +e
	for id in "${virtual_keys[@]:-}"; do
		curl -sS -H "Cookie: $admin_cookie" -X DELETE "$BASE/api/governance/virtual-keys/$id" >/dev/null
	done
	for id in "${users[@]:-}"; do
		curl -sS -H "Cookie: $admin_cookie" -X DELETE "$BASE/api/enterprise/users/$id" >/dev/null
	done
	for id in "${roles[@]:-}"; do
		curl -sS -H "Cookie: $admin_cookie" -X DELETE "$BASE/api/roles/$id" >/dev/null
	done
	for id in "${teams[@]:-}"; do
		curl -sS -H "Cookie: $admin_cookie" -X DELETE "$BASE/api/governance/teams/$id" >/dev/null
	done
}

require_jq() {
	if ! command -v jq >/dev/null 2>&1; then
		echo "jq is required"
		exit 2
	fi
}

create_role() {
	local name="$1"
	local permissions="$2"
	local create_out role_id
	create_out="$(post_json /api/roles "$admin_cookie" "{\"name\":\"$name\",\"description\":\"VK role permission smoke test\"}")"
	if [[ "$(status "$create_out")" != "200" ]]; then
		echo "failed to create role $name: $(body "$create_out")"
		exit 1
	fi
	role_id="$(body "$create_out" | jq -r '.id')"
	roles+=("$role_id")
	put_json "/api/roles/$role_id/permissions" "$admin_cookie" "$permissions" >/dev/null
}

create_team() {
	local name="$1"
	local create_out team_id
	create_out="$(post_json /api/governance/teams "$admin_cookie" "{\"name\":\"$name\"}")"
	if [[ "$(status "$create_out")" != "200" ]]; then
		echo "failed to create team $name: $(body "$create_out")"
		exit 1
	fi
	team_id="$(body "$create_out" | jq -r '.team.id')"
	teams+=("$team_id")
	echo "$team_id"
}

create_user() {
	local email="$1"
	local name="$2"
	local role="$3"
	local team_id="$4"
	local payload create_out user_id
	payload="{\"email\":\"$email\",\"name\":\"$name\",\"password\":\"$PASSWORD\",\"role\":\"$role\",\"team_id\":\"$team_id\"}"
	create_out="$(post_json /api/enterprise/users "$admin_cookie" "$payload")"
	if [[ "$(status "$create_out")" != "200" ]]; then
		echo "failed to create user $email: $(body "$create_out")"
		exit 1
	fi
	user_id="$(body "$create_out" | jq -r '.id')"
	users+=("$user_id")
}

create_virtual_key() {
	local name="$1"
	local team_id="$2"
	local cookie="$3"
	local out vk_id
	out="$(post_json /api/governance/virtual-keys "$cookie" "{\"name\":\"$name\",\"team_id\":\"$team_id\",\"provider_configs\":[{\"provider\":\"openai\",\"weight\":1,\"allowed_models\":[],\"key_ids\":[]}],\"mcp_configs\":[],\"is_active\":true}")"
	if [[ "$(status "$out")" != "200" ]]; then
		echo "failed to create virtual key $name: $(body "$out")"
		exit 1
	fi
	vk_id="$(body "$out" | jq -r '.virtual_key.id')"
	virtual_keys+=("$vk_id")
	echo "$vk_id"
}

main() {
	require_jq

	admin_cookie="$(login "$ADMIN_EMAIL" "$ADMIN_PASSWORD")"
	if [[ -z "$admin_cookie" ]]; then
		echo "failed to login as admin"
		exit 1
	fi
	trap cleanup EXIT

	local team_a team_b viewer_email developer_email vk_manager_email vk_manager_role
	team_a="$(create_team "VK-Perms-Team-A-$NOW")"
	team_b="$(create_team "VK-Perms-Team-B-$NOW")"
	viewer_email="vk-viewer-$NOW@test.com"
	developer_email="vk-developer-$NOW@test.com"
	vk_manager_email="vk-manager-$NOW@test.com"
	vk_manager_role="VK-Manager-$NOW"

	create_role "$vk_manager_role" '[{"resource":"VirtualKeys","operation":"View"},{"resource":"VirtualKeys","operation":"Create"},{"resource":"VirtualKeys","operation":"Update"},{"resource":"VirtualKeys","operation":"Delete"},{"resource":"Teams","operation":"View"},{"resource":"Customers","operation":"View"}]'

	create_user "$viewer_email" "VK Viewer" "Viewer" "$team_a"
	create_user "$developer_email" "VK Developer" "Developer" "$team_a"
	create_user "$vk_manager_email" "VK Manager" "$vk_manager_role" "$team_a"

	local viewer_cookie developer_cookie vk_manager_cookie
	viewer_cookie="$(login "$viewer_email" "$PASSWORD")"
	developer_cookie="$(login "$developer_email" "$PASSWORD")"
	vk_manager_cookie="$(login "$vk_manager_email" "$PASSWORD")"

	local admin_team_b_vk developer_team_a_vk manager_team_a_vk
	admin_team_b_vk="$(create_virtual_key "admin-team-b-vk-$NOW" "$team_b" "$admin_cookie")"
	developer_team_a_vk="$(create_virtual_key "developer-team-a-vk-$NOW" "$team_a" "$developer_cookie")"
	manager_team_a_vk="$(create_virtual_key "manager-team-a-vk-$NOW" "$team_a" "$vk_manager_cookie")"

	local failures=0
	local out code

	out="$(get_req /api/governance/virtual-keys "$viewer_cookie")"
	code="$(status "$out")"
	assert_status "Viewer cannot list VKs" "$code" "403" || failures=$((failures + 1))

	out="$(post_json /api/governance/virtual-keys "$viewer_cookie" "{\"name\":\"viewer-create-$NOW\",\"team_id\":\"$team_a\",\"provider_configs\":[{\"provider\":\"openai\",\"weight\":1,\"allowed_models\":[],\"key_ids\":[]}],\"mcp_configs\":[],\"is_active\":true}")"
	code="$(status "$out")"
	assert_status "Viewer cannot create VK" "$code" "403" || failures=$((failures + 1))

	out="$(get_req /api/governance/virtual-keys "$developer_cookie")"
	code="$(status "$out")"
	assert_status "Developer can list team VKs" "$code" "200" || failures=$((failures + 1))
	if [[ "$code" == "200" ]]; then
		printf 'INFO Developer visible VK names: %s\n' "$(body "$out" | jq -c '[.virtual_keys[].name]')"
	fi

	out="$(get_req "/api/governance/virtual-keys/$admin_team_b_vk" "$developer_cookie")"
	code="$(status "$out")"
	assert_status "Developer cannot read cross-team admin VK" "$code" "403" || failures=$((failures + 1))

	out="$(delete_req "/api/governance/virtual-keys/$admin_team_b_vk" "$developer_cookie")"
	code="$(status "$out")"
	assert_status "Developer cannot delete cross-team admin VK" "$code" "403" || failures=$((failures + 1))

	out="$(get_req "/api/governance/virtual-keys/$manager_team_a_vk" "$developer_cookie")"
	code="$(status "$out")"
	printf 'CHECK Developer read same-team manager VK got=%s expected=200 for team-scope, 403 for owner-scope\n' "$code"

	out="$(get_req "/api/governance/virtual-keys/$developer_team_a_vk" "$vk_manager_cookie")"
	code="$(status "$out")"
	printf 'CHECK VK Manager read same-team developer VK got=%s expected=200 for team-scope, 403 for owner-scope\n' "$code"

	out="$(delete_req "/api/governance/virtual-keys/$developer_team_a_vk" "$vk_manager_cookie")"
	code="$(status "$out")"
	printf 'CHECK VK Manager delete same-team developer VK got=%s expected=403 if owner-safe\n' "$code"
	if [[ "$code" == "200" ]]; then
		# It is already gone.
		virtual_keys=("${virtual_keys[@]/$developer_team_a_vk}")
	fi

	out="$(put_json "/api/governance/virtual-keys/$manager_team_a_vk" "$developer_cookie" "{\"name\":\"developer-updated-manager-vk-$NOW\"}")"
	code="$(status "$out")"
	printf 'CHECK Developer update same-team manager VK got=%s expected=403 if owner-safe\n' "$code"

	if [[ "$failures" -gt 0 ]]; then
		echo "RESULT FAIL: $failures required checks failed"
		exit 1
	fi

	echo "RESULT PASS: required cross-team/viewer checks passed"
	echo "NOTE: CHECK lines are policy decisions. If you require owner-safe VK management, got=200 on same-team delete/update is a bug to fix."
}

main "$@"
