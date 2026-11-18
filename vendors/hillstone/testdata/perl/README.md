# Perl reference artifacts

`hillstone-search.json` was produced by running the Perl reference implementation (`algosec/backend/lib/Firewall`, `Firewall::Policy::Searcher::searchPolicy`) through `search.pl` on the synthetic `hillstone.cfg`:

```sh
perl -I /path/to/algosec/backend/lib search.pl hillstone < hillstone.cfg > hillstone-search.json
```

Regeneration needs Perl 5.44 with Moose and JSON::PP installed. The files were copied unchanged from firemon v0.2 (`analysis/testdata/perl-business`). `perl_test.go` pins the v2 design decision for each case against the Perl result type (ignore, modify, new); ADR 0003 lists the intended semantic differences.
