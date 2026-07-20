//go:build !goexperiment.runtimesecret

package secretdo

// Do invokes f directly. When built with GOEXPERIMENT=runtimesecret,
// this is replaced by the real runtime/secret.Do which erases
// registers, stack, and heap used by f after it returns.
func Do(f func()) { f() }
