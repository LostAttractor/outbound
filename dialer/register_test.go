package dialer

import (
	"errors"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

type registerTestDialer struct{}

func (*registerTestDialer) Dialer(_ *ExtraOption, parent netproxy.Dialer) (netproxy.Dialer, error) {
	return parent, nil
}

func TestNewFromLinkParsesOneLinkAndPreservesAlias(t *testing.T) {
	const scheme = "registertest"
	var receivedLink string
	var creatorCalls int
	wantDialer := new(registerTestDialer)
	fromLinkCreators[scheme] = func(link string) (Dialer, *Property, error) {
		creatorCalls++
		receivedLink = link
		return wantDialer, &Property{Name: "parsed name", Link: link}, nil
	}
	t.Cleanup(func() { delete(fromLinkCreators, scheme) })

	tests := []struct {
		name  string
		alias string
		link  string
	}{
		{
			name:  "literal arrows",
			alias: "alias->name",
			link:  scheme + "://example.com/path->part?value=left->right#fragment->part",
		},
		{
			name:  "encoded arrows",
			alias: "alias%2D%3Ename",
			link:  scheme + "://example.com/path%2D%3Eother://part?value=left%2D%3Eother://query#fragment%2D%3Eother://part",
		},
		{
			name:  "arrows before schemes in URL components",
			alias: "component arrows",
			link:  scheme + "://example.com/path->other://part?value=left->other://query#fragment->other://part",
		},
		{
			name:  "spaced arrows in query and fragment",
			alias: "spaced component arrows",
			link:  scheme + "://example.com/path?value=left -> other://query#fragment -> other://part",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receivedLink = ""
			creatorCalls = 0
			dialers, property, err := NewFromLink(tt.alias + ":  " + tt.link + "  ")
			if err != nil {
				t.Fatal(err)
			}
			if len(dialers) != 1 || dialers[0] != wantDialer {
				t.Fatalf("dialers = %#v, want one registered dialer", dialers)
			}
			if receivedLink != tt.link {
				t.Fatalf("creator received %q, want %q", receivedLink, tt.link)
			}
			if creatorCalls != 1 {
				t.Fatalf("creator calls = %d, want 1", creatorCalls)
			}
			if property.Name != tt.alias {
				t.Fatalf("property name = %q, want alias %q", property.Name, tt.alias)
			}
		})
	}
}

func TestNewFromLinkRejectsLegacyShareLinkProxyChain(t *testing.T) {
	const scheme = "registerchain"
	creatorCalled := false
	fromLinkCreators[scheme] = func(string) (Dialer, *Property, error) {
		creatorCalled = true
		return new(registerTestDialer), new(Property), nil
	}
	t.Cleanup(func() { delete(fromLinkCreators, scheme) })

	for _, link := range []string{
		"alias:" + scheme + "://first.example/path ->  other+share://second.example",
		"alias:" + scheme + "://first.example->other+share://second.example",
		"alias:" + scheme + "://first.example/path->" + scheme + "://second.example",
		"alias:" + scheme + "://first.example/path?x=y -> " + scheme + "://second.example",
	} {
		dialers, property, err := NewFromLink(link)
		if !errors.Is(err, ErrLegacyShareLinkProxyChain) {
			t.Fatalf("link %q: error = %v, want ErrLegacyShareLinkProxyChain", link, err)
		}
		if dialers != nil || property != nil {
			t.Fatalf("link %q: dialers, property = %#v, %#v; want nil results", link, dialers, property)
		}
	}
	if creatorCalled {
		t.Fatal("creator was called for a legacy chain")
	}
}
