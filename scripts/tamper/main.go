// Command tamper edits a COPY of a Tollgate audit log the way an attacker
// covering their tracks would: it turns the first deny into an allow. It is
// used by scripts/demo.sh to show that `tollgate verify` catches the edit.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/timeomy/tollgate/internal/store"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: tamper AUDIT_DB_COPY")
		os.Exit(2)
	}
	ctx := context.Background()
	db, err := store.OpenExisting(ctx, os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()
	for _, q := range []string{
		"DROP TRIGGER IF EXISTS events_no_update",
		"UPDATE events SET decision='allow', reason='permitted' WHERE seq = (SELECT MIN(seq) FROM events WHERE decision='deny')",
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	fmt.Println("tampered: first denied call now says 'allow'")
}
