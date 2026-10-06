package collect

import "time"

func timeoutAfterASecond() <-chan time.Time { return time.After(time.Second) }
