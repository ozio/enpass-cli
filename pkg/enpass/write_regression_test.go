package enpass

import (
	"bytes"
	"github.com/sirupsen/logrus"
	"strings"
	"testing"
	"time"
)

func writableFixture(t *testing.T) *Vault {
	t.Helper()
	v, err := NewVault(copyTestVault(t), logrus.ErrorLevel)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	if err := v.Open(&VaultCredentials{Password: testPassword}); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTOTPWriteRoundTrip(t *testing.T) {
	v := writableFixture(t)
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	id, err := v.CreateEntry(&EntryData{Title: "TOTP only", TOTP: secret})
	if err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		fields, err := v.GetAllFields("totp", []string{"TOTP only"})
		if err != nil {
			t.Fatal(err)
		}
		if len(fields) != 1 {
			t.Fatalf("TOTP field count=%d", len(fields))
		}
		value, err := fields[0].Decrypt()
		if err != nil || value != want {
			t.Fatal("TOTP did not round trip")
		}
		var uid, position, updated int64
		if err := v.db.QueryRow("SELECT item_field_uid,orde,value_updated_at FROM itemfield WHERE item_uuid=? AND type='totp'", id).Scan(&uid, &position, &updated); err != nil {
			t.Fatal(err)
		}
		if uid <= 0 || position < 0 || updated <= 0 {
			t.Fatal("missing field metadata")
		}
	}
	check(secret)
	uri := "otpauth://totp/Example?secret=" + secret + "&digits=8&period=60&algorithm=SHA1"
	if err := v.UpdateEntry(id, &EntryData{TOTP: uri}); err != nil {
		t.Fatal(err)
	}
	check(uri)
	if code, err := ComputeTOTP(uri, time.Unix(59, 0)); err != nil || code != "84755224" {
		t.Fatalf("unexpected RFC code %q: %v", code, err)
	}
	if err := v.UpdateEntry(id, &EntryData{ClearFields: []string{"totp"}}); err != nil {
		t.Fatal(err)
	}
	check("")
}

func TestWriteRejectsInvalidTOTPAtomically(t *testing.T) {
	v := writableFixture(t)
	id, err := v.CreateEntry(&EntryData{Title: "Before invalid", Password: "unchanged"})
	if err != nil {
		t.Fatal(err)
	}
	bad := "otpauth://totp/test?secret=SHOULDNOTAPPEAR&digits=999"
	if err := v.UpdateEntry(id, &EntryData{Title: "Should roll back", TOTP: bad}); err == nil || strings.Contains(err.Error(), "SHOULDNOTAPPEAR") {
		t.Fatal("invalid TOTP validation or redaction failed")
	}
	c, err := v.GetEntryByUUID(id)
	if err != nil || c.Title != "Before invalid" {
		t.Fatal("invalid update changed entry")
	}
	if _, err := v.CreateEntry(&EntryData{Title: "Invalid create", TOTP: bad}); err == nil {
		t.Fatal("invalid create accepted")
	}
}

func TestEditDoesNotCorruptOtherPasswords(t *testing.T) {
	v := writableFixture(t)
	card, err := v.GetEntry("password", []string{"Whatever"}, true)
	if err != nil {
		t.Fatal(err)
	}
	before, err := v.GetAllFields("password", []string{"Whatever"})
	if err != nil {
		t.Fatal(err)
	}
	if len(before) < 2 {
		t.Fatal("fixture must contain multiple passwords")
	}
	if err := v.UpdateEntry(card.UUID, &EntryData{Title: "Should roll back", Password: "new"}); err == nil {
		t.Fatal("ambiguous password update accepted")
	}
	after, err := v.GetAllFields("password", []string{"Whatever"})
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatal("entry was changed")
	}
	for i := range before {
		a, e1 := before[i].Decrypt()
		b, e2 := after[i].Decrypt()
		if e1 != nil || e2 != nil || a != b || !bytes.Equal(before[i].itemKey, after[i].itemKey) {
			t.Fatal("other password was corrupted")
		}
	}
}

func TestEditPreservesHistoryAndDeletedFields(t *testing.T) {
	v := writableFixture(t)
	id, err := v.CreateEntry(&EntryData{Title: "History guard", Password: "original", URL: "https://before.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.db.Exec("UPDATE itemfield SET history='opaque-history' WHERE item_uuid=? AND type='password'", id); err != nil {
		t.Fatal(err)
	}
	if err := v.UpdateEntry(id, &EntryData{Password: "new", URL: "https://after.test"}); err == nil {
		t.Fatal("history protection missing")
	}
	if _, err := v.db.Exec("UPDATE itemfield SET deleted=1 WHERE item_uuid=? AND type='url'", id); err != nil {
		t.Fatal(err)
	}
	if err := v.UpdateEntry(id, &EntryData{URL: "https://after.test"}); err != nil {
		t.Fatal(err)
	}
	var oldValue string
	var deleted int
	if err := v.db.QueryRow("SELECT value,deleted FROM itemfield WHERE item_uuid=? AND type='url' ORDER BY ID LIMIT 1", id).Scan(&oldValue, &deleted); err != nil {
		t.Fatal(err)
	}
	if oldValue != "https://before.test" || deleted != 1 {
		t.Fatal("tombstone changed")
	}
}

func TestExplicitClearAndMissingEntry(t *testing.T) {
	v := writableFixture(t)
	id, err := v.CreateEntry(&EntryData{Title: "Clear me", Username: "before", Password: "before", Notes: "before", URL: "https://before.test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.UpdateEntry(id, &EntryData{ClearFields: []string{"login", "password", "url", "notes"}}); err != nil {
		t.Fatal(err)
	}
	var subtitle, note string
	if err := v.db.QueryRow("SELECT subtitle,note FROM item WHERE uuid=?", id).Scan(&subtitle, &note); err != nil {
		t.Fatal(err)
	}
	if subtitle != "" || note != "" {
		t.Fatal("metadata not cleared")
	}
	fields, err := v.GetAllFields("", []string{"Clear me"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range fields {
		value, err := c.Decrypt()
		if err != nil || value != "" {
			t.Fatal("field not cleared")
		}
	}
	if err := v.UpdateEntry("missing", &EntryData{Title: "new"}); err == nil {
		t.Fatal("missing entry accepted")
	}
	if err := v.UpdateEntry(id, &EntryData{}); err == nil {
		t.Fatal("empty patch accepted")
	}
	if err := v.UpdateEntry(id, &EntryData{TOTP: "JBSWY3DPEHPK3PXP", ClearFields: []string{"totp"}}); err == nil {
		t.Fatal("conflicting patch accepted")
	}
}

func TestPasswordEditPreservesUnknownSensitiveFields(t *testing.T) {
	v := writableFixture(t)
	id, err := v.CreateEntry(&EntryData{Title: "Unknown field guard", Password: "original"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.db.Exec(`INSERT INTO itemfield(item_uuid,item_field_uid,type,value,sensitive,deleted) VALUES(?,99,'future-secret-type','opaque-ciphertext',1,0)`, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.UpdateEntry(id, &EntryData{Password: "replacement"}); err == nil {
		t.Fatal("unknown sensitive field was not protected")
	}
}
