package validate

import (
	"fmt"
)

// Just some super simple shared validation/err utils

// TODO: Needs more time and effort
func LazyErr(argname string) error {
	return fmt.Errorf("the value for %s is invalid", argname)
}
