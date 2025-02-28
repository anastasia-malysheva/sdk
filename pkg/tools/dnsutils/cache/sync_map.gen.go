// Code generated by "-output sync_map.gen.go -type msgMap<github.com/miekg/dns.Question,*github.com/miekg/dns.Msg> -output sync_map.gen.go -type msgMap<github.com/miekg/dns.Question,*github.com/miekg/dns.Msg>"; DO NOT EDIT.
package cache

import (
	"sync" // Used by sync.Map.

	"github.com/miekg/dns"
)

// Generate code that will fail if the constants change value.
func _() {
	// An "cannot convert msgMap literal (type msgMap) to type sync.Map" compiler error signifies that the base type have changed.
	// Re-run the go-syncmap command to generate them again.
	_ = (sync.Map)(msgMap{})
}

var _nil_msgMap_dns_Msg_value = func() (val *dns.Msg) { return }()

// Load returns the value stored in the map for a key, or nil if no
// value is present.
// The ok result indicates whether value was found in the map.
func (m *msgMap) Load(key dns.Question) (*dns.Msg, bool) {
	value, ok := (*sync.Map)(m).Load(key)
	if value == nil {
		return _nil_msgMap_dns_Msg_value, ok
	}
	return value.(*dns.Msg), ok
}

// Store sets the value for a key.
func (m *msgMap) Store(key dns.Question, value *dns.Msg) {
	(*sync.Map)(m).Store(key, value)
}

// LoadOrStore returns the existing value for the key if present.
// Otherwise, it stores and returns the given value.
// The loaded result is true if the value was loaded, false if stored.
func (m *msgMap) LoadOrStore(key dns.Question, value *dns.Msg) (*dns.Msg, bool) {
	actual, loaded := (*sync.Map)(m).LoadOrStore(key, value)
	if actual == nil {
		return _nil_msgMap_dns_Msg_value, loaded
	}
	return actual.(*dns.Msg), loaded
}

// LoadAndDelete deletes the value for a key, returning the previous value if any.
// The loaded result reports whether the key was present.
func (m *msgMap) LoadAndDelete(key dns.Question) (value *dns.Msg, loaded bool) {
	actual, loaded := (*sync.Map)(m).LoadAndDelete(key)
	if actual == nil {
		return _nil_msgMap_dns_Msg_value, loaded
	}
	return actual.(*dns.Msg), loaded
}

// Delete deletes the value for a key.
func (m *msgMap) Delete(key dns.Question) {
	(*sync.Map)(m).Delete(key)
}

// Range calls f sequentially for each key and value present in the map.
// If f returns false, range stops the iteration.
//
// Range does not necessarily correspond to any consistent snapshot of the Map's
// contents: no key will be visited more than once, but if the value for any key
// is stored or deleted concurrently, Range may reflect any mapping for that key
// from any point during the Range call.
//
// Range may be O(N) with the number of elements in the map even if f returns
// false after a constant number of calls.
func (m *msgMap) Range(f func(key dns.Question, value *dns.Msg) bool) {
	(*sync.Map)(m).Range(func(key, value interface{}) bool {
		return f(key.(dns.Question), value.(*dns.Msg))
	})
}
