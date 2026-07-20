//go:build goexperiment.runtimesecret

package secretdo

import "runtime/secret"

// Do wraps runtime/secret.Do to erase registers, stack, and heap used by f.
func Do(f func()) { secret.Do(f) }
