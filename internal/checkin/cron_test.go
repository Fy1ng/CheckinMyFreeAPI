package checkin

import (
	"testing"
	"time"
)

func localTime(value string) time.Time {
	v, _ := time.ParseInLocation("2006-01-02T15:04:05", value, LocalTimezone)
	return v
}
func TestCronCalendarAndUTC8Compatibility(t *testing.T) {
	for _, tc := range []struct{ expression, after, next string }{{"0 8 * * *", "2026-10-25T07:59:59", "2026-10-25T08:00:00"}, {"0 8 * * *", "2026-10-25T08:00:00", "2026-10-26T08:00:00"}, {"0,30 8-10/2 * * 1-5", "2026-10-23T10:30:00", "2026-10-26T08:00:00"}, {"0 8 * * 7", "2026-10-24T12:00:00", "2026-10-25T08:00:00"}, {"0 8 * * 0", "2026-10-24T12:00:00", "2026-10-25T08:00:00"}, {"0 8 1 * 1", "2026-10-25T12:00:00", "2026-10-26T08:00:00"}, {"0 8 1 * 1", "2026-10-31T12:00:00", "2026-11-01T08:00:00"}, {"0 8 29 2 *", "2026-10-25T12:00:00", "2028-02-29T08:00:00"}, {"0 8 */2 * 1", "2026-10-25T12:00:00", "2026-11-09T08:00:00"}, {"0 8 * * */2", "2026-10-25T12:00:00", "2026-10-27T08:00:00"}} {
		t.Run(tc.expression+tc.after, func(t *testing.T) {
			cron, err := ParseCron(tc.expression)
			if err != nil {
				t.Fatal(err)
			}
			next, err := cron.NextAfter(localTime(tc.after))
			if err != nil || !next.Equal(localTime(tc.next)) {
				t.Fatalf("got %s/%v, want %s", next, err, tc.next)
			}
		})
	}
}
func TestCronRejectsInvalidAndFrequent(t *testing.T) {
	for _, expression := range []string{"* * * * *", "*/15 * * * *", "0,45 * * * *", "0 0 31 2 *", "0 0 * * MON", "@daily", "* * * * * *", "60 0 * * *", "0 24 * * *", "0 0 * * 8", "0 0 */0 * *", "0 0 3-1 * *", "0 0 1,,2 * *", "0 0 * * */-1", "0 0 * * 1/", "0 0 * * 1/999999999999999999999999"} {
		if _, err := ParseCron(expression); err == nil {
			t.Fatalf("accepted %s", expression)
		}
	}
}
func TestDailyTimeExclusiveAndValidated(t *testing.T) {
	next, err := NextDailyTime("23:55", localTime("2026-10-25T23:55:00"))
	if err != nil || !next.Equal(localTime("2026-10-26T23:55:00")) {
		t.Fatal(next, err)
	}
	for _, value := range []string{"8:00", "24:00", "08:60", "", "08:00\n"} {
		if _, err := NextDailyTime(value, time.Now()); err == nil {
			t.Fatal("accepted invalid clock")
		}
	}
}
