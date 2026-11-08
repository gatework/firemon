package snapshot_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/snapshot"
)

func TestTypedWeeklySnapshotRestoresEvidenceAndIsolatedIntervals(t *testing.T) {
	at := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
	original, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "synthetic", Vendor: "asa"}, Raw: "not reparsable native configuration",
		Schedules: []fm.ScheduleRecord{{Object: fm.Object{ID: "weekly"}, Timezone: "UTC", Calendar: fm.CalendarCivil, Weekly: []fm.WeeklyPeriod{{Start: at, End: at.AddDate(1, 0, 0), Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 17 * time.Hour}}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := snapshot.Encode(&encoded, original); err != nil {
		t.Fatal(err)
	}
	old := bytes.Clone(encoded.Bytes())
	old[10], old[11] = 0, 9
	if _, err := snapshot.Decode(bytes.NewReader(old), snapshot.DefaultMaxBytes); !errors.Is(err, snapshot.ErrFormat) {
		t.Fatal("obsolete untyped schedule semantics loaded", err)
	}
	restored, err := snapshot.Decode(&encoded, snapshot.DefaultMaxBytes)
	if err != nil || !restored.Complete() || restored.SemanticDigest() != original.SemanticDigest() || restored.Raw() != original.Raw() {
		t.Fatal("typed schedule snapshot changed semantics", err)
	}
	data := restored.Export()
	data.Schedules[0].Weekly[0].Windows[0].End = time.Hour
	if active, known := restored.Schedule("weekly").ActiveAt(at); !known || !active {
		t.Fatal("restored schedule lost typed calendar or immutable windows", active, known)
	}
	if expired, known := restored.Schedule("weekly").ExpiredAt(at.AddDate(-1, 0, 0)); !known || expired {
		t.Fatal("future schedule became expired after load", expired, known)
	}
}
