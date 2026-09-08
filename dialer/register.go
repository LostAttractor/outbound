/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"errors"
	"fmt"
	"strings"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/common/url"
)

type FromLinkCreator func(link string) (builder Builder, property *Property, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[strings.ToLower(name)] = creator
}

func NewFromLink(link string) (Builder, *Property, error) {
	/// Get overwritten name.
	overwrittenName, linklike := common.GetTagFromLinkLikePlaintext(link)
	linklike = strings.TrimSpace(linklike)
	u, err := url.Parse(linklike)
	if err != nil {
		// URL errors include the original link, which can contain credentials.
		var parseErr *url.Error
		if errors.As(err, &parseErr) {
			err = parseErr.Err
		}
		return nil, nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	creator, ok := fromLinkCreators[strings.ToLower(u.Scheme)]
	if !ok {
		return nil, nil, fmt.Errorf("unexpected link type: %v", u.Scheme)
	}
	s, property, err := creator(linklike)
	if err != nil {
		return nil, nil, fmt.Errorf("create %s proxy: %w", u.Scheme, err)
	}
	if overwrittenName != "" {
		property.Name = overwrittenName
	}
	return s, property, nil
}
