#!/usr/bin/env sh
# shellcheck disable=SC2034
dns_exoscale_info='Exoscale.com
Site: Exoscale.com
Docs: github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_exoscale
Options:
 EXOSCALE_API_KEY API Key
 EXOSCALE_SECRET_KEY API Secret key
'

EXOSCALE_API=https://api-ch-gva-2.exoscale.com/v2

########  Public functions #####################

# Usage: add  _acme-challenge.www.domain.com   "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
# Used to add txt record
dns_exoscale_add() {
  fulldomain=$1
  txtvalue=$2

  if ! _checkAuth; then
    return 1
  fi

  _debug "First detect the root zone"
  if ! _get_root "$fulldomain"; then
    _err "invalid domain"
    return 1
  fi

  _debug _sub_domain "$_sub_domain"
  _debug _domain "$_domain"

  _info "Adding record"
  if _exoscale_rest POST "dns-domain/$_domain_id/record" "{\"name\":\"$_sub_domain\",\"type\":\"TXT\",\"content\":\"$txtvalue\",\"ttl\":120}"; then
    if _contains "$response" "\"state\":\"success\""; then
      _info "Added, OK"
      return 0
    fi
  fi
  _err "Add txt record error."
  return 1
}

# Usage: fulldomain txtvalue
# Used to remove the txt record after validation
dns_exoscale_rm() {
  fulldomain=$1
  txtvalue=$2

  if ! _checkAuth; then
    return 1
  fi

  _debug "First detect the root zone"
  if ! _get_root "$fulldomain"; then
    _err "invalid domain"
    return 1
  fi

  _debug _sub_domain "$_sub_domain"
  _debug _domain "$_domain"

  _debug "Getting txt records"
  _exoscale_rest GET "dns-domain/${_domain_id}/record" ""
  if _contains "$response" "\"name\":\"$_sub_domain\"" >/dev/null; then
    _record_id=$(echo "$response" | tr '{' "\n" | grep "$txtvalue" | _egrep_o "id\":\"[^\"]*\"" | _head_n 1 | cut -d : -f 2 | tr -d \")
  fi

  _debug "Record id: $_record_id"
  _debug "Domain id: $_domain_id"
  _debug "Sub domain: $_sub_domain"
  _debug "Domain: $_domain"
  _debug "Txt value: $txtvalue"
  _debug "Response: $response"

  if [ -z "$_record_id" ]; then
    _err "Can not get record id to remove."
    return 1
  fi

  _debug "Deleting record $_record_id"

  if ! _exoscale_rest DELETE "dns-domain/$_domain_id/record/$_record_id" ""; then
    _err "Delete record error."
    return 1
  fi

  return 0
}

####################  Private functions below ##################################

_checkAuth() {
  EXOSCALE_API_KEY="${EXOSCALE_API_KEY:-$(_readaccountconf_mutable EXOSCALE_API_KEY)}"
  EXOSCALE_SECRET_KEY="${EXOSCALE_SECRET_KEY:-$(_readaccountconf_mutable EXOSCALE_SECRET_KEY)}"

  if [ -z "$EXOSCALE_API_KEY" ] || [ -z "$EXOSCALE_SECRET_KEY" ]; then
    EXOSCALE_API_KEY=""
    EXOSCALE_SECRET_KEY=""
    _err "You don't specify Exoscale application key and application secret yet."
    _err "Please create you key and try again."
    return 1
  fi

  _saveaccountconf_mutable EXOSCALE_API_KEY "$EXOSCALE_API_KEY"
  _saveaccountconf_mutable EXOSCALE_SECRET_KEY "$EXOSCALE_SECRET_KEY"

  return 0
}

#_acme-challenge.www.domain.com
#returns
# _sub_domain=_acme-challenge.www
# _domain=domain.com
# _domain_id=sdjkglgdfewsdfg
_get_root() {

  if ! _exoscale_rest GET "dns-domain"; then
    return 1
  fi

  domain=$1
  i=2
  p=1
  while true; do
    h=$(printf "%s" "$domain" | cut -d . -f "$i"-100)
    _debug h "$h"
    if [ -z "$h" ]; then
      #not valid
      return 1
    fi

    if _contains "$response" "\"unicode-name\":\"$h\"" >/dev/null; then
      _domain_id=$(_extract_domain_id "$response" "$h")
      if [ "$_domain_id" ]; then
        _sub_domain=$(printf "%s" "$domain" | cut -d . -f 1-"$p")
        _domain=$h
        return 0
      fi
      return 1
    fi
    p=$i
    i=$(_math "$i" + 1)
  done
  return 1
}

_extract_domain_id() {
  json="$1"
  domain_name="$2"

  echo "$json" | grep "\"unicode-name\":\"$domain_name\"" | \
    sed -n 's/.*"id":"\([^"]*\)".*/\1/p'
}

_generate_signature() {
  method=$1
  path=$2
  body=$3
  timestamp=$(($(date +%s) + 600))

  message=$(printf "%s /v2/%s\n%s\n\n\n%s" "$method" "$path" "$body" "$timestamp")

  # Compute HMAC SHA-256 signature
  signature=$(printf "%s" "$message" | openssl dgst -sha256 -hmac "$EXOSCALE_SECRET_KEY" -binary | base64)

  # Construct Authorization header
  auth_header="EXO2-HMAC-SHA256 credential=$EXOSCALE_API_KEY,expires=$timestamp,signature=$signature"
  echo "$auth_header"
}

# returns response
_exoscale_rest() {
  method="$1"
  path="$2"
  data="$3"
  request_url="$EXOSCALE_API/$path"
  _debug "$path"

  export _H1="Accept: application/json"

  signature=$(_generate_signature "$method" "$path" "$data")
  export _H2="Authorization: $signature"

  if [ "$data" ] || [ "$method" = "DELETE" ]; then
    export _H3="Content-Type: application/json"
    _debug data "$data"
    response="$(_post "$data" "$request_url" "" "$method")"
  else
    response="$(_get "$request_url" "" "" "$method")"
  fi

  if [ "$?" != "0" ]; then
    _err "error $request_url"
    return 1
  fi
  _debug2 response "$response"
  return 0
}
