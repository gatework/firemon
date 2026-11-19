package intake_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/intake"
	"github.com/gatework/firemon/traffic"
)

func book() firemon.ServiceBook {
	b, _ := firemon.ParseServiceBook([]byte(`{"HTTPS":["tcp/443"],"SSH":["tcp/22"],"DNS":["tcp/53","udp/53"]}`))
	return b
}

func codes(notes []intake.Note) []intake.Code {
	var out []intake.Code
	for _, n := range notes {
		out = append(out, n.Code)
	}
	return out
}

func TestParse_Addresses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
		code           intake.Code
	}{
		{"mixed separators", "10.0.0.1，10.0.0.2、10.0.0.3; 10.0.0.4\n10.0.0.5", "10.0.0.1-10.0.0.5", intake.CodeUnset},
		{"host bits cleared", "10.1.1.9/24", "10.1.1.0/24", intake.CodeMasked},
		{"address and mask", "10.2.0.0 255.255.0.0", "10.2.0.0/16", intake.CodeMask},
		{"slash mask", "10.3.0.0/255.255.255.0", "10.3.0.0/24", intake.CodeUnset},
		{"short range", "10.1.1.1-9", "10.1.1.1-10.1.1.9", intake.CodeShortRange},
		{"tilde range", "10.1.1.1~10.1.1.3", "10.1.1.1-10.1.1.3", intake.CodeUnset},
		{"wildcard", "10.4.*.*", "10.4.0.0/16", intake.CodeWildcard},
		{"duplicates", "10.0.0.0/8, 10.1.1.1", "10.0.0.0/8", intake.CodeDuplicate},
		{"ipv6", "2001:db8::1", "2001:db8::1", intake.CodeUnset},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req, err := intake.Parse(tt.in, "any", "any", intake.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if req.Src.String() != tt.want {
				t.Fatalf("got %s, want %s", req.Src, tt.want)
			}
			if tt.code != intake.CodeUnset && !slices.Contains(codes(req.Notes), tt.code) {
				t.Fatalf("notes %v lack %s", req.Notes, tt.code)
			}
		})
	}
}

func TestParse_Services(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"bare port is tcp", "443", "tcp/443"},
		{"protocol and port", "tcp 80, udp:53", "tcp/80,udp/53"},
		{"port then protocol", "8080/tcp", "tcp/8080"},
		{"inherited protocol", "udp/53,54", "udp/53-54"},
		{"range", "tcp/8000-8010", "tcp/8000-8010"},
		{"names ignore case", "https,ssh", "tcp/22,tcp/443"},
		{"ping", "ping", "icmp/8"},
		{"protocol number", "proto/89", "89"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req, err := intake.Parse("any", "any", tt.in, intake.Options{Services: book()})
			if err != nil {
				t.Fatal(err)
			}
			if req.Service.String() != tt.want {
				t.Fatalf("got %s, want %s (notes %v)", req.Service, tt.want, req.Notes)
			}
		})
	}
}

func TestParse_DomainsAndApplications(t *testing.T) {
	t.Parallel()
	isApp := func(n string) bool { return n == "ms-rdp" || n == "ssh" }
	req, err := intake.Parse("10.0.0.1", "Account.Live.COM., *.example.com", "app:ssh, ms-rdp", intake.Options{IsApplication: isApp})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(req.DstDomains, []string{"*.example.com", "account.live.com"}) || !req.Dst.IsEmpty() {
		t.Fatalf("domains %v dst %s", req.DstDomains, req.Dst)
	}
	if !slices.Equal(req.Applications, []string{"ms-rdp", "ssh"}) || !req.Service.IsAny() {
		t.Fatalf("apps %v service %s", req.Applications, req.Service)
	}
}

// TestParse_UnknownApplicationFails: an application no book knows is not
// guessed at; the request fails rather than being answered for the rest.
func TestParse_UnknownApplicationFails(t *testing.T) {
	t.Parallel()
	isApp := func(n string) bool { return n == "ssh" }
	req, err := intake.Parse("10.0.0.1", "10.0.0.2", "tcp/443, app:nosuchapp", intake.Options{IsApplication: isApp})
	if !errors.Is(err, intake.ErrInvalidItem) || !slices.Contains(codes(req.Notes), intake.CodeUnknownApplication) {
		t.Fatalf("err %v notes %v", err, req.Notes)
	}
	if _, err := intake.Parse("10.0.0.1", "10.0.0.2", "tcp/443, 10.0.0.1.1", intake.Options{}); !errors.Is(err, intake.ErrInvalidItem) {
		t.Fatalf("an unreadable item fails the request: %v", err)
	}
}

func TestParse_PortZeroFails(t *testing.T) {
	t.Parallel()
	for _, svc := range []string{"tcp/0", "0", "udp 0"} {
		if _, err := intake.Parse("10.0.0.1", "10.0.0.2", svc, intake.Options{}); !errors.Is(err, intake.ErrInvalidItem) {
			t.Errorf("%s: err %v", svc, err)
		}
	}
	if _, err := intake.Parse("10.0.0.1", "10.0.0.2", "tcp/0-65535", intake.Options{}); err != nil {
		t.Fatalf("every port: %v", err)
	}
}

func TestParse_FamilyMismatchFails(t *testing.T) {
	t.Parallel()
	if _, err := intake.Parse("10.0.0.1", "2001:db8::1", "tcp/443", intake.Options{}); !errors.Is(err, intake.ErrFamilyMismatch) {
		t.Fatalf("err %v", err)
	}
	if _, err := intake.Parse("10.0.0.1, 2001:db8::2", "2001:db8::1", "tcp/443", intake.Options{}); err != nil {
		t.Fatalf("one family in common is a request: %v", err)
	}
}

func TestParse_SkipsInvalidAndFailsOnEmpty(t *testing.T) {
	t.Parallel()
	req, err := intake.Parse("10.0.0.1, 999.1.1.1, www.example.com", "bogus!", "tcp/99999", intake.Options{})
	if !errors.Is(err, intake.ErrNoDestination) || !errors.Is(err, intake.ErrNoService) || errors.Is(err, intake.ErrNoSource) {
		t.Fatalf("err %v", err)
	}
	if req.Src.String() != "10.0.0.1" || !slices.Contains(codes(req.Notes), intake.CodeUnsupported) {
		t.Fatalf("source domains are not usable: %v", req.Notes)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("10.0.0.1-9，10.1.*.*", "a.example.com 10.2.0.0 255.255.0.0", "tcp 80, 443/udp, https")
	f.Fuzz(func(t *testing.T, src, dst, svc string) {
		req, _ := intake.Parse(src, dst, svc, intake.Options{Services: book()})
		for _, n := range req.Notes {
			if n.Input == "" {
				t.Fatalf("note without input: %+v", n)
			}
		}
		if !req.Src.IsEmpty() && !traffic.AnyAddress().ContainsSet(req.Src) {
			t.Fatal("source outside the address space")
		}
	})
}
