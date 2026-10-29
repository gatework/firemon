package fortinet

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func (p *parser) settings(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	defer tx.Rollback()
	seen := make(map[string]bool)
	for _, key := range []string{"system global", "system settings"} {
		for _, section := range p.sections[key] {
			borders(tx, section)
			for _, r := range section.Members {
				if err := ctx.Err(); err != nil {
					return err
				}
				w := r.Words
				if len(w) != 3 || w[0] != "set" || seen[w[1]] {
					continue
				}
				seen[w[1]] = true
				valid := false
				if key == "system global" && w[1] == "default-service-source-port" {
					if value, ok := ports(w[2]); ok {
						p.sourcePorts = value
						valid = true
					}
				}
				if key == "system settings" {
					valid = (w[1] == "central-nat" && w[2] == "disable") || (w[1] == "ngfw-mode" && w[2] == "profile-based")
				}
				if valid {
					tx.Parse(r.Lines()...)
				}
			}
		}
	}
	return p.commit(s, tx, fm.Data{})
}
