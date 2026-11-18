STANDARDS_DIR ?=
include standard.mk

.PHONY: fuzz corpus

CHECK_EXTRA += fuzz

# Short fuzz passes over the algebra and both vendor parsers.
fuzz:
	$(GO) test -run '^$$' -fuzz '^FuzzRegion$$' -fuzztime=10s ./traffic
	$(GO) test -run '^$$' -fuzz '^FuzzDomainSet$$' -fuzztime=10s ./traffic
	$(GO) test -run '^$$' -fuzz '^FuzzParse$$' -fuzztime=10s ./vendors/hillstone
	$(GO) test -run '^$$' -fuzz '^FuzzParse$$' -fuzztime=10s ./vendors/paloalto
	$(GO) test -run '^$$' -fuzz '^FuzzParseHits$$' -fuzztime=10s ./vendors/hillstone
	$(GO) test -run '^$$' -fuzz '^FuzzParseHits$$' -fuzztime=10s ./vendors/paloalto
	$(GO) test -run '^$$' -fuzz '^FuzzTranslate$$' -fuzztime=10s ./migrate
	$(GO) test -run '^$$' -fuzz '^FuzzParse$$' -fuzztime=10s ./intake

# Parses the private configuration corpus named by FIREMON_CORPUS (TST-3).
corpus:
	@test -n "$(FIREMON_CORPUS)" || { echo "set FIREMON_CORPUS to a directory of device configurations"; exit 1; }
	$(GO) test -count=1 -run Corpus -v ./vendors/... | grep -E '^(=== RUN|--- |\s+corpus_test|ok|FAIL)'
