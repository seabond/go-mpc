.PHONY: test test-race test-secret test-verbose bench cover lint vet staticcheck ci

# Run all tests
test:
	go test ./...

# Run tests with race detector
test-race:
	go test -race -timeout 120s ./...

# Run tests with runtime/secret memory erasure (linux/amd64 and linux/arm64 only)
test-secret:
	GOEXPERIMENT=runtimesecret go test -race -timeout 120s ./...

# Run tests with verbose output
test-verbose:
	go test -v ./dkls23
	go test -v ./frost

# Run benchmarks
bench:
	go test -bench=. -benchmem ./dkls23
	go test -bench=. -benchmem ./frost

# Show test coverage
cover:
	go test -coverprofile=coverage.out ./dkls23 ./frost
	go tool cover -func=coverage.out | tail -1
	@rm -f coverage.out

# Run go vet
vet:
	go vet ./...

# Run staticcheck
staticcheck:
	go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
	go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...

# Run all linters
lint: vet staticcheck

# Run the full CI pipeline locally
ci: lint test-race cover
