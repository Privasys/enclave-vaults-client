// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

// Approval binding v2.
//
// An approval names the constellation it is for: the member ids of its vaults,
// each the hash of a key that vault generated itself. A vault refuses an
// approval whose member set does not contain its own id, so an approval made
// for one constellation (dev, say) cannot be spent on another (production).
//
// Every form here is UTF-8 text, lines joined by "\n", no trailing newline. A
// missing value is "-". A value containing "\n" is refused. Sets are sorted
// ascending by byte value. The vault rebuilds the text from its own state and
// the request's content; it never takes a digest from a request.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	bindingV2Domain     = "privasys-vault-approval/v2"
	memberIDDomain      = "privasys-vault-member-v1\n"
	vaultIdentityDomain = "privasys-vault-identity-v1"

	// BindingMaxTTLSeconds is the furthest ahead a binding's exp may be.
	BindingMaxTTLSeconds = 600
)

// BindingOp is the operation a v2 binding approves.
type BindingOp string

const (
	BindCreate          BindingOp = "create"
	BindPromote         BindingOp = "promote"
	BindExport          BindingOp = "export"
	BindExportAssembled BindingOp = "export_assembled"
	BindIssuerCreate    BindingOp = "issuer_create"
	BindIssuerUpdate    BindingOp = "issuer_update"
	BindIssuerDelete    BindingOp = "issuer_delete"
	BindUpdatePolicy    BindingOp = "update_policy"
	BindDelete          BindingOp = "delete"
	BindReshare         BindingOp = "reshare"
	BindRevokePending   BindingOp = "revoke_pending"
)

func (o BindingOp) valid() bool {
	switch o {
	case BindCreate, BindPromote, BindExport, BindExportAssembled, BindIssuerCreate,
		BindIssuerUpdate, BindIssuerDelete, BindUpdatePolicy, BindDelete, BindReshare, BindRevokePending:
		return true
	}
	return false
}

// MemberID is a vault's id in a constellation: hex SHA-256 of
// "privasys-vault-member-v1\n" followed by the SEC1 uncompressed public key of
// the member key it generated in its enclave.
func MemberID(memberPubSEC1 []byte) (string, error) {
	if len(memberPubSEC1) != 65 || memberPubSEC1[0] != 0x04 {
		return "", errors.New("member key: not a SEC1 uncompressed P-256 point")
	}
	h := sha256.New()
	h.Write([]byte(memberIDDomain))
	h.Write(memberPubSEC1)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// IdentityReportData is the report data of a vault's identity quote:
// SHA-256 of "privasys-vault-identity-v1\n" member_id "\n" billing_id.
func IdentityReportData(memberID, billingID string) [32]byte {
	return sha256.Sum256([]byte(vaultIdentityDomain + "\n" + memberID + "\n" + billingID))
}

// BindingV2 is the operation an approval authorises, on the vaults it names.
type BindingV2 struct {
	Members       []string  // member ids, hex; sorted when the text is built
	Op            BindingOp //
	Handle        string    // key handle, or the issuer_id for issuer ops
	Target        string    // computed per op; "" is written as "-"
	PolicyVersion uint64    // the version the operation replaces; 0 for create
	Approver      string    // holder_id, or "oidc:<issuer index>:<sub>"
	HolderHead    string    // hex; "" (issuer approvals) is written as "-"
	Nonce         string    // 16 random bytes, b64u
	Exp           int64     // unix seconds
}

// OidcApprover is the approver line of an issuer approval.
func OidcApprover(issuerIndex uint32, sub string) string {
	return "oidc:" + strconv.FormatUint(uint64(issuerIndex), 10) + ":" + sub
}

// Text is the binding's canonical text: what a phone signs, and what an issuer
// approval's vault_op hashes.
func (b BindingV2) Text() (string, error) {
	if len(b.Members) == 0 {
		return "", errors.New("binding: no members")
	}
	members := append([]string(nil), b.Members...)
	sort.Strings(members)
	for i, m := range members {
		if len(m) != 64 || strings.ToLower(m) != m {
			return "", fmt.Errorf("binding: member %q is not a lowercase hex member id", m)
		}
		if _, err := hex.DecodeString(m); err != nil {
			return "", fmt.Errorf("binding: member %q is not a lowercase hex member id", m)
		}
		if i > 0 && members[i-1] == m {
			return "", fmt.Errorf("binding: member %s is listed twice", m)
		}
	}
	if !b.Op.valid() {
		return "", fmt.Errorf("binding: unknown operation %q", b.Op)
	}
	if b.Handle == "" || b.Approver == "" || b.Nonce == "" {
		return "", errors.New("binding: handle, approver and nonce are required")
	}
	if b.Exp <= 0 {
		return "", errors.New("binding: no expiry")
	}
	lines := make([]string, 0, 10+len(members))
	lines = append(lines, bindingV2Domain, strconv.Itoa(len(members)))
	lines = append(lines, members...)
	lines = append(lines,
		string(b.Op), b.Handle, orDash(b.Target),
		strconv.FormatUint(b.PolicyVersion, 10),
		b.Approver, orDash(b.HolderHead), b.Nonce,
		strconv.FormatInt(b.Exp, 10))
	for _, l := range lines {
		if strings.ContainsAny(l, "\n\r") {
			return "", errors.New("binding: a value contains a line break")
		}
	}
	return strings.Join(lines, "\n"), nil
}

// VaultOp is b64u(SHA-256(text)): the vault_op claim of an issuer approval,
// and an entry digest in a batch.
func (b BindingV2) VaultOp() (string, error) {
	t, err := b.Text()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(t))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ===========================================================================
//  Policy digest: PD(policy) = hex SHA-256 of the policy's JCS form (RFC 8785)
// ===========================================================================

// PolicyDigestJSON is PD of a policy given as JSON. Policies hold no
// fractional numbers, so any number that is not an integer within ±2^53 is
// refused rather than given an encoding the other implementations might not
// share.
func PolicyDigestJSON(policy []byte) (string, error) {
	c, err := CanonicalJSON(policy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// PolicyDigest is PD of a policy as this client sends it.
func PolicyDigest(p KeyPolicy) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return PolicyDigestJSON(raw)
}

// CanonicalJSON is the RFC 8785 form of a JSON document whose numbers are all
// integers within ±2^53.
func CanonicalJSON(doc []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	v, err := readJSONValue(dec)
	if err != nil {
		return nil, fmt.Errorf("canonical json: %w", err)
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("canonical json: trailing data")
	}
	var out bytes.Buffer
	if err := writeJCS(&out, v); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// readJSONValue decodes one value and refuses an object that names a member
// twice: decoders disagree on which copy wins, so such a document could mean
// one thing to the approver and another to the vault.
func readJSONValue(dec *json.Decoder) (interface{}, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]interface{}{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, dup := obj[k]; dup {
					return nil, fmt.Errorf("member %q appears twice", k)
				}
				v, err := readJSONValue(dec)
				if err != nil {
					return nil, err
				}
				obj[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []interface{}{}
			for dec.More() {
				v, err := readJSONValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		return tok, nil
	}
}

func writeJCS(w *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case nil:
		w.WriteString("null")
	case bool:
		if t {
			w.WriteString("true")
		} else {
			w.WriteString("false")
		}
	case json.Number:
		n, err := jcsInteger(string(t))
		if err != nil {
			return err
		}
		w.WriteString(n)
	case string:
		return writeJCSString(w, t)
	case []interface{}:
		w.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				w.WriteByte(',')
			}
			if err := writeJCS(w, e); err != nil {
				return err
			}
		}
		w.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// RFC 8785 §3.2.3: members sorted by their names as UTF-16 code units.
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		w.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				w.WriteByte(',')
			}
			if err := writeJCSString(w, k); err != nil {
				return err
			}
			w.WriteByte(':')
			if err := writeJCS(w, t[k]); err != nil {
				return err
			}
		}
		w.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unexpected %T", v)
	}
	return nil
}

// jcsInteger accepts the integers ES6 serialises exactly, and writes them as
// it does: no exponent, no fraction, no "-0".
var maxExactInt = new(big.Int).Lsh(big.NewInt(1), 53)

func jcsInteger(s string) (string, error) {
	// Parsed exactly: a float parse would round 2^53+1 to 2^53 and digest a
	// number nobody wrote.
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return "", fmt.Errorf("canonical json: number %s is not readable", s)
	}
	if !r.IsInt() || new(big.Int).Abs(r.Num()).Cmp(maxExactInt) > 0 {
		return "", fmt.Errorf("canonical json: number %s is not an integer within 2^53", s)
	}
	return r.Num().String(), nil
}

// writeJCSString escapes as ES6 JSON.stringify does: '"', '\\' and the
// control characters only; everything else is written as UTF-8.
func writeJCSString(w *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("canonical json: a string is not valid UTF-8")
	}
	w.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			w.WriteString(`\"`)
		case '\\':
			w.WriteString(`\\`)
		case '\b':
			w.WriteString(`\b`)
		case '\f':
			w.WriteString(`\f`)
		case '\n':
			w.WriteString(`\n`)
		case '\r':
			w.WriteString(`\r`)
		case '\t':
			w.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(w, `\u%04x`, r)
			} else {
				w.WriteRune(r)
			}
		}
	}
	w.WriteByte('"')
	return nil
}

func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
