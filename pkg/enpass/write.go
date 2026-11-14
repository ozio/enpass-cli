package enpass

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// EntryData holds values to create or update. Empty values are unchanged during
// updates; ClearFields explicitly clears login, password, url, notes, or totp.
type EntryData struct {
	Title       string
	Username    string
	Password    string
	URL         string
	Notes       string
	Category    string
	TOTP        string
	ClearFields []string
}

func (e *EntryData) validate() (map[string]bool, error) {
	if e == nil {
		return nil, errors.New("entry data is required")
	}
	if e.Title != "" && strings.TrimSpace(e.Title) == "" {
		return nil, errors.New("title cannot be blank")
	}
	values := map[string]string{"login": e.Username, "password": e.Password, "url": e.URL, "notes": e.Notes, "totp": e.TOTP}
	clear := make(map[string]bool)
	for _, name := range e.ClearFields {
		if _, ok := values[name]; !ok {
			return nil, fmt.Errorf("unsupported field to clear: %s", name)
		}
		if values[name] != "" {
			return nil, fmt.Errorf("cannot set and clear %s together", name)
		}
		clear[name] = true
	}
	if e.TOTP != "" {
		if _, err := ComputeTOTP(e.TOTP, time.Unix(0, 0)); err != nil {
			// Never attach the URI/base32 value or parser errors containing it.
			return nil, errors.New("invalid TOTP secret or otpauth parameters")
		}
	}
	return clear, nil
}

// insertField assigns an entry-local field ID and display position. Values live
// inside the encrypted database; only password fields use the additional item key.
func insertField(tx *sql.Tx, id, kind, label, value string, sensitive bool, now int64) error {
	_, err := tx.Exec(`INSERT INTO itemfield
        (item_uuid,item_field_uid,label,value,deleted,sensitive,historical,type,
         updated_at,value_updated_at,orde,history)
        SELECT ?,COALESCE(MAX(item_field_uid),0)+1,?,?,0,?,0,?,?,?,COALESCE(MAX(orde),-1)+1,''
        FROM itemfield WHERE item_uuid=?`, id, label, value, sensitive, kind, now, now, id)
	return errors.Wrap(err, "could not insert field")
}

func (v *Vault) CreateEntry(entry *EntryData) (string, error) {
	if v.db == nil {
		return "", errors.New("vault is not initialized")
	}
	if _, err := entry.validate(); err != nil {
		return "", err
	}
	if strings.TrimSpace(entry.Title) == "" {
		return "", errors.New("title is required")
	}
	if len(entry.ClearFields) != 0 {
		return "", errors.New("clear fields is only supported for updates")
	}
	id, now := uuid.NewString(), time.Now().Unix()
	category := entry.Category
	if category == "" {
		category = "Login"
	}
	tx, err := v.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	// Generate a valid item key even for entries initially lacking a password.
	encrypted, key, err := EncryptValue(entry.Password, id)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(`INSERT INTO item
        (uuid,created_at,field_updated_at,updated_at,title,subtitle,note,trashed,deleted,category,icon,last_used,key)
        VALUES (?,?,?,?,?,?,?,0,0,?,?,?,?)`, id, now, now, now, entry.Title, entry.Username, entry.Notes, category, "card_password", now, key)
	if err != nil {
		return "", errors.Wrap(err, "could not insert item")
	}
	fields := []struct {
		kind, label, value string
		sensitive          bool
	}{
		{"username", "Username", entry.Username, false},
		{"password", "Password", encrypted, true},
		{"url", "Website", entry.URL, false},
		{"totp", "TOTP", entry.TOTP, true},
	}
	for _, f := range fields {
		if f.kind == "password" && entry.Password == "" {
			continue
		}
		if f.value == "" {
			continue
		}
		if err := insertField(tx, id, f.kind, f.label, f.value, f.sensitive, now); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return id, nil
}

// singleField refuses ambiguous edits rather than overwriting every field of a type.
func singleField(tx *sql.Tx, id, kind string) (int64, error) {
	rows, err := tx.Query(`SELECT ID FROM itemfield WHERE item_uuid=? AND type=? AND COALESCE(deleted,0)=0`, id, kind)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var found int64
	for rows.Next() {
		var next int64
		if err := rows.Scan(&next); err != nil {
			return 0, err
		}
		if found != 0 {
			return 0, fmt.Errorf("multiple %s fields; edit this entry in Enpass", kind)
		}
		found = next
	}
	return found, rows.Err()
}

// UpdateEntry applies the entire patch atomically and never revives deleted fields.
func (v *Vault) UpdateEntry(id string, updates *EntryData) error {
	if v.db == nil {
		return errors.New("vault is not initialized")
	}
	clear, err := updates.validate()
	if err != nil {
		return err
	}
	if updates.Title == "" && updates.Username == "" && updates.Password == "" && updates.URL == "" && updates.Notes == "" && updates.Category == "" && updates.TOTP == "" && len(clear) == 0 {
		return errors.New("no changes requested")
	}
	tx, err := v.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow(`SELECT 1 FROM item WHERE uuid=? AND COALESCE(deleted,0)=0 AND COALESCE(trashed,0)=0`, id).Scan(&exists); err != nil {
		return errors.New("active entry not found")
	}
	now := time.Now().Unix()
	for _, f := range []struct {
		column, value string
		set           bool
	}{
		{"title", updates.Title, updates.Title != ""}, {"subtitle", updates.Username, updates.Username != "" || clear["login"]},
		{"note", updates.Notes, updates.Notes != "" || clear["notes"]}, {"category", updates.Category, updates.Category != ""},
	} {
		if f.set {
			if _, err := tx.Exec("UPDATE item SET "+f.column+"=? WHERE uuid=?", f.value, id); err != nil {
				return err
			}
		}
	}
	for _, f := range []struct {
		name, kind, label, value string
		sensitive                bool
	}{
		{"login", "username", "Username", updates.Username, false},
		{"password", "password", "Password", updates.Password, true},
		{"url", "url", "Website", updates.URL, false},
		{"totp", "totp", "TOTP", updates.TOTP, true},
	} {
		if f.value == "" && !clear[f.name] {
			continue
		}
		fieldID, err := singleField(tx, id, f.kind)
		if err != nil {
			return err
		}
		value := f.value
		if f.kind == "password" && value != "" {
			// Replacing item.key would invalidate all other ciphertext and
			// password history. Until these formats are reconstructed, refuse.
			var dependent int
			err := tx.QueryRow(`SELECT COUNT(*) FROM itemfield WHERE item_uuid=? AND
                ((((COALESCE(sensitive,0)=1 AND type!='totp') OR type IN ('password','ccTxnpassword')) AND ID != ? AND COALESCE(value,'')!='')
                 OR COALESCE(history,'') NOT IN ('','[]'))`, id, fieldID).Scan(&dependent)
			if err != nil {
				return err
			}
			if dependent > 0 {
				return errors.New("password update requires re-encrypting other fields or history; edit this entry in Enpass")
			}
			encrypted, key, err := EncryptValue(value, id)
			if err != nil {
				return err
			}
			value = encrypted
			if _, err := tx.Exec(`UPDATE item SET key=? WHERE uuid=?`, key, id); err != nil {
				return err
			}
		}
		if fieldID == 0 {
			if value == "" {
				continue
			}
			if err := insertField(tx, id, f.kind, f.label, value, f.sensitive, now); err != nil {
				return err
			}
		} else {
			_, err := tx.Exec(`UPDATE itemfield SET value=?,sensitive=?,updated_at=?,value_updated_at=? WHERE ID=?`, value, f.sensitive, now, now, fieldID)
			if err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`UPDATE item SET field_updated_at=?,updated_at=? WHERE uuid=?`, now, now, id); err != nil {
		return err
	}
	return tx.Commit()
}

// TrashEntry moves an entry to the trash
func (v *Vault) TrashEntry(entryUUID string) error {
	if v.db == nil {
		return errors.New("vault is not initialized")
	}

	now := time.Now().Unix()
	result, err := v.db.Exec("UPDATE item SET trashed = 1, field_updated_at = ? WHERE uuid = ?", now, entryUUID)
	if err != nil {
		return errors.Wrap(err, "could not trash entry")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("entry not found")
	}

	v.logger.WithField("uuid", entryUUID).Debug("trashed entry")
	return nil
}

// RestoreEntry restores an entry from the trash
func (v *Vault) RestoreEntry(entryUUID string) error {
	if v.db == nil {
		return errors.New("vault is not initialized")
	}

	now := time.Now().Unix()
	result, err := v.db.Exec("UPDATE item SET trashed = 0, field_updated_at = ? WHERE uuid = ?", now, entryUUID)
	if err != nil {
		return errors.Wrap(err, "could not restore entry")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("entry not found")
	}

	v.logger.WithField("uuid", entryUUID).Debug("restored entry")
	return nil
}

// DeleteEntry permanently deletes an entry from the vault
func (v *Vault) DeleteEntry(entryUUID string) error {
	if v.db == nil {
		return errors.New("vault is not initialized")
	}

	// Start transaction
	tx, err := v.db.Begin()
	if err != nil {
		return errors.Wrap(err, "could not begin transaction")
	}
	defer tx.Rollback()

	// Delete from itemfield first (foreign key constraint)
	_, err = tx.Exec("DELETE FROM itemfield WHERE item_uuid = ?", entryUUID)
	if err != nil {
		return errors.Wrap(err, "could not delete item fields")
	}

	// Delete from item
	result, err := tx.Exec("DELETE FROM item WHERE uuid = ?", entryUUID)
	if err != nil {
		return errors.Wrap(err, "could not delete item")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("entry not found")
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "could not commit transaction")
	}

	v.logger.WithField("uuid", entryUUID).Debug("deleted entry")
	return nil
}

// GetEntryByUUID retrieves a single entry by its UUID (including trashed)
func (v *Vault) GetEntryByUUID(entryUUID string) (*Card, error) {
	if v.db == nil {
		return nil, errors.New("vault is not initialized")
	}

	row := v.db.QueryRow(`
		SELECT item.uuid, itemfield.type, item.created_at, item.field_updated_at, item.title,
		       item.subtitle, item.note, item.trashed, item.deleted, item.category,
		       itemfield.label, itemfield.value, item.key, item.last_used, itemfield.sensitive, item.icon
		FROM item
		INNER JOIN itemfield ON item.uuid = itemfield.item_uuid
		WHERE item.uuid = ? AND itemfield.sensitive = 1
		LIMIT 1
	`, entryUUID)

	var card Card
	err := row.Scan(
		&card.UUID, &card.Type, &card.CreatedAt, &card.UpdatedAt, &card.Title,
		&card.Subtitle, &card.Note, &card.Trashed, &card.Deleted, &card.Category,
		&card.Label, &card.value, &card.itemKey, &card.LastUsed, &card.Sensitive, &card.Icon,
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve entry")
	}

	card.RawValue = card.value
	return &card, nil
}
