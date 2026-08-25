/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/common/url"
)

type FromLinkCreator func(link string) (dialer Dialer, property *Property, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

var (
	// ErrLegacyShareLinkProxyChain reports the removed link1->link2 syntax.
	ErrLegacyShareLinkProxyChain = errors.New("legacy share-link proxy chains are no longer supported")
	legacyShareLinkProxyChain    = regexp.MustCompile(`\s+->\s+([A-Za-z][A-Za-z0-9+.-]*)://`)
	compactLegacyShareLinkChain  = regexp.MustCompile(`->([A-Za-z][A-Za-z0-9+.-]*)://`)
)

func isLegacyShareLinkProxyChain(link string) bool {
	chainCandidate := link
	componentStart := strings.IndexAny(chainCandidate, "?#")
	if componentStart >= 0 {
		chainCandidate = chainCandidate[:componentStart]
	}
	for _, match := range legacyShareLinkProxyChain.FindAllStringSubmatchIndex(link, -1) {
		if componentStart < 0 || match[0] < componentStart {
			return true
		}
		if _, registered := fromLinkCreators[link[match[2]:match[3]]]; registered {
			return true
		}
	}

	// A compact chain after the URL authority is indistinguishable from an
	// ordinary path component. A registered next scheme disambiguates it;
	// otherwise reject only the authority form.
	schemeEnd := strings.Index(chainCandidate, "://")
	if schemeEnd < 0 {
		return false
	}
	authorityEnd := len(chainCandidate)
	if i := strings.IndexByte(chainCandidate[schemeEnd+3:], '/'); i >= 0 {
		authorityEnd = schemeEnd + 3 + i
	}
	for _, match := range compactLegacyShareLinkChain.FindAllStringSubmatchIndex(link, -1) {
		if match[0] < schemeEnd+3 {
			continue
		}
		if _, registered := fromLinkCreators[link[match[2]:match[3]]]; registered {
			return true
		}
		if match[0] < authorityEnd {
			return true
		}
	}
	return false
}

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[name] = creator
}

func NewFromLink(link string) (dialers []Dialer, property *Property, err error) {
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
	creator, ok := fromLinkCreators[u.Scheme]
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
