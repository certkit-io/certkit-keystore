package utils

import (
	"fmt"
	"time"
)

func FormatTimezone() string {
	name, offset := time.Now().Zone()
	hours := offset / 3600
	minutes := (offset % 3600) / 60
	if minutes < 0 {
		minutes = -minutes
	}
	return fmt.Sprintf("%s%+d:%02d", name, hours, minutes)
}
