package checkin

import (
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var LocalTimezone = time.FixedZone("Asia/Singapore", 8*60*60)
var cronCharacters = regexp.MustCompile(`^[0-9*/,-]+$`)
var clockPattern = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)

type Cron struct {
	minutes, hours, days, months, weekdays map[int]bool
	times                                  []int
	dayWildcard, weekdayWildcard           bool
}

func cronField(text string, lower, upper int) (map[int]bool, error) {
	bad := errors.New("Cron supports bounded numeric five-field expressions")
	if !cronCharacters.MatchString(text) {
		return nil, bad
	}
	values := make(map[int]bool)
	for _, item := range strings.Split(text, ",") {
		parts := strings.Split(item, "/")
		if len(parts) > 2 {
			return nil, bad
		}
		step := 1
		if len(parts) == 2 {
			n, e := strconv.Atoi(parts[1])
			if e != nil || n < 1 {
				return nil, bad
			}
			step = n
		}
		var start, end int
		base := parts[0]
		switch {
		case base == "*":
			start, end = lower, upper
		case strings.Contains(base, "-"):
			bounds := strings.Split(base, "-")
			if len(bounds) != 2 {
				return nil, bad
			}
			var e error
			start, e = strconv.Atoi(bounds[0])
			if e != nil {
				return nil, bad
			}
			end, e = strconv.Atoi(bounds[1])
			if e != nil {
				return nil, bad
			}
		default:
			var e error
			start, e = strconv.Atoi(base)
			if e != nil {
				return nil, bad
			}
			end = start
			if len(parts) == 2 {
				end = upper
			}
		}
		if start < lower || end > upper || start > end {
			return nil, bad
		}
		for n := start; n <= end; {
			values[n] = true
			if step > end-n {
				break
			}
			n += step
		}
	}
	return values, nil
}

func ParseCron(expression string) (*Cron, error) {
	if len(expression) > 128 {
		return nil, errors.New("Cron expression too long")
	}
	f := strings.Fields(expression)
	if len(f) != 5 {
		return nil, errors.New("Cron requires five fields")
	}
	c := &Cron{dayWildcard: strings.HasPrefix(f[2], "*"), weekdayWildcard: strings.HasPrefix(f[4], "*")}
	sets := []*map[int]bool{&c.minutes, &c.hours, &c.days, &c.months, &c.weekdays}
	bounds := [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	for i := range sets {
		v, e := cronField(f[i], bounds[i][0], bounds[i][1])
		if e != nil {
			return nil, e
		}
		*sets[i] = v
	}
	if c.weekdays[7] {
		c.weekdays[0] = true
		delete(c.weekdays, 7)
	}
	for h := range c.hours {
		for m := range c.minutes {
			c.times = append(c.times, h*60+m)
		}
	}
	sort.Ints(c.times)
	for i, v := range c.times {
		next := c.times[(i+1)%len(c.times)]
		if i == len(c.times)-1 {
			next += 1440
		}
		if next-v < 30 {
			return nil, errors.New("Cron times must be at least 30 minutes apart")
		}
	}
	_, err := c.NextAfter(time.Date(2024, 1, 1, 0, 0, 0, 0, LocalTimezone))
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cron) NextAfter(after time.Time) (time.Time, error) {
	local := after.In(LocalTimezone)
	midnight := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, LocalTimezone)
	for offset := 0; offset <= 366*8; offset++ {
		day := midnight.AddDate(0, 0, offset)
		if !c.months[int(day.Month())] {
			continue
		}
		dom, dow := c.days[day.Day()], c.weekdays[int(day.Weekday())]
		matches := dom || dow
		if c.dayWildcard || c.weekdayWildcard {
			matches = dom && dow
		}
		if !matches {
			continue
		}
		for _, minute := range c.times {
			candidate := day.Add(time.Duration(minute) * time.Minute)
			if candidate.After(local) {
				return candidate, nil
			}
		}
	}
	return time.Time{}, errors.New("Cron has no occurrence within eight years")
}

func NextDailyTime(clock string, after time.Time) (time.Time, error) {
	if !clockPattern.MatchString(clock) {
		return time.Time{}, errors.New("daily time must use HH:MM in UTC+8")
	}
	h, _ := strconv.Atoi(clock[:2])
	m, _ := strconv.Atoi(clock[3:])
	local := after.In(LocalTimezone)
	candidate := time.Date(local.Year(), local.Month(), local.Day(), h, m, 0, 0, LocalTimezone)
	if !candidate.After(local) {
		candidate = candidate.AddDate(0, 0, 1)
	}
	return candidate, nil
}
