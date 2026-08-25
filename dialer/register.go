/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/common/url"
)

type FromLinkCreator func(link string) (dialer Dialer, property *Property, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

// ErrLegacyShareLinkProxyChain reports the removed link1->link2 syntax.
var ErrLegacyShareLinkProxyChain = errors.New("legacy share-link proxy chains are no longer supported")

func isLegacyShareLinkProxyChain(link string) bool {
	componentStart := strings.IndexAny(link, "?#")
	chainEnd := len(link)
	if componentStart >= 0 {
		chainEnd = componentStart
	}

	// A compact chain after the URL authority is indistinguishable from an
	// ordinary path component. A registered next scheme disambiguates it;
	// otherwise reject only the authority form.
	schemeEnd := strings.Index(link[:chainEnd], "://")
	authorityEnd := chainEnd
	if schemeEnd >= 0 {
		if i := strings.IndexByte(link[schemeEnd+3:chainEnd], '/'); i >= 0 {
			authorityEnd = schemeEnd + 3 + i
		}
	}
	for search := 0; search < len(link); {
		i := strings.Index(link[search:], "->")
		if i < 0 {
			break
		}
		arrowStart := search + i
		search = arrowStart + 2

		afterArrow := link[search:]
		nextLink := strings.TrimLeftFunc(afterArrow, unicode.IsSpace)
		next, err := url.Parse(nextLink)
		if err != nil || next.Scheme == "" || !strings.HasPrefix(nextLink[len(next.Scheme):], "://") {
			continue
		}
		if _, registered := fromLinkCreators[strings.ToLower(next.Scheme)]; registered {
			return true
		}
		if arrowStart >= chainEnd {
			continue
		}
		left, _ := utf8.DecodeLastRuneInString(link[:arrowStart])
		spaced := unicode.IsSpace(left) || len(nextLink) != len(afterArrow)
		if spaced || (schemeEnd >= 0 && arrowStart < authorityEnd) {
			return true
		}
	}
	return false
}

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[strings.ToLower(name)] = creator
}

func NewFromLink(link string) ([]Dialer, *Property, error) {
	/// Get overwritten name.
	overwrittenName, linklike := common.GetTagFromLinkLikePlaintext(link)
	linklike = strings.TrimSpace(linklike)
	if isLegacyShareLinkProxyChain(linklike) {
		return nil, nil, ErrLegacyShareLinkProxyChain
	}
	u, err := url.Parse(linklike)
	if err != nil {
		return nil, nil, err
	}
	creator, ok := fromLinkCreators[strings.ToLower(u.Scheme)]
	if !ok {
		return nil, nil, fmt.Errorf("unexpected link type: %v", u.Scheme)
	}
	s, property, err := creator(linklike)
	if err != nil {
		return nil, nil, fmt.Errorf("create %v: %w", linklike, err)
	}
	if overwrittenName != "" {
		property.Name = overwrittenName
	}
	return []Dialer{s}, property, nil
}
