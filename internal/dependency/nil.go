// Package dependency checks nil values at injected dependency boundaries.
package dependency

import "reflect"

// Nil includes an interface containing a typed nil pointer, function, or container.
func Nil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
