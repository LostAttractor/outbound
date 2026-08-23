package meek

import "context"

type Request struct {
	Data          []byte
	ConnectionTag []byte
}

type Tripper interface {
	RoundTrip(ctx context.Context, req Request) (resp Response, err error)
}

type Response struct {
	Data []byte
}
