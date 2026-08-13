package common

import (
	"context"
)

func Invoke[R any](ctx context.Context, fn func() (R, error), cb func()) (res R, err error) {
	type result struct {
		value R
		err   error
	}
	resultChan := make(chan result, 1)

	go func() {
		value, err := fn()
		resultChan <- result{value, err}
	}()

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case result := <-resultChan:
		res, err = result.value, result.err
	}

	if err != nil && cb != nil {
		cb()
	}

	return
}
