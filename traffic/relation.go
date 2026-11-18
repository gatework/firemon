package traffic

// Relation classifies how one set relates to another. Unlike a plain
// subset test it tells partial overlap apart from disjointness.
type Relation uint8

// Relation values, from the receiver's point of view.
const (
	// RelationUnset is the zero value; comparisons never return it.
	RelationUnset Relation = iota
	// RelationEqual means both sets hold exactly the same members.
	RelationEqual
	// RelationSuperset means the receiver strictly contains the other set.
	RelationSuperset
	// RelationSubset means the receiver is strictly contained by the other set.
	RelationSubset
	// RelationOverlap means the sets share members but neither contains the other.
	RelationOverlap
	// RelationDisjoint means the sets share no member.
	RelationDisjoint
)

var relationNames = [...]string{"unset", "equal", "superset", "subset", "overlap", "disjoint"}

// String returns the lower-case relation name.
func (r Relation) String() string {
	if int(r) < len(relationNames) {
		return relationNames[r]
	}
	return "invalid"
}

// Valid reports whether r is a known relation other than RelationUnset.
func (r Relation) Valid() bool { return r > RelationUnset && r <= RelationDisjoint }

// Covers reports whether the receiver of the comparison contains the other
// set, that is the relation is RelationEqual or RelationSuperset.
func (r Relation) Covers() bool { return r == RelationEqual || r == RelationSuperset }

// relate derives a Relation from the four set facts every algebra can answer.
func relate(equal, superset, subset, overlap bool) Relation {
	switch {
	case equal:
		return RelationEqual
	case superset:
		return RelationSuperset
	case subset:
		return RelationSubset
	case overlap:
		return RelationOverlap
	default:
		return RelationDisjoint
	}
}
