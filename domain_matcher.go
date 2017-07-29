package dnsproxy

// check if a domain in
// 	- gfw list
// 	- obedient list
//	- neither
type DomainMatcher interface {
	MatchGFW(domain string) bool
	MatchObedient(domain string) bool
}
