NAME := nomad-plugin-firecracker
PKG := github.com/dantoml/$(NAME)

CGO_ENABLED := 0

# Set any default go build tags.
BUILDTAGS :=
# Set an output prefix, which is the local directory if not specified
PREFIX?=$(shell pwd)

# Set the build dir, where built cross-compiled binaries will be output
BUILDDIR := ${PREFIX}/dist

GOOSARCHES=linux/amd64

GO=go

.PHONY: build
build: $(NAME) ## Builds a dynamic executable or package.

$(NAME): $(wildcard *.go) $(wildcard */*.go)
	@echo "+ $@"
	$(GO) build -tags "$(BUILDTAGS)" ${GO_LDFLAGS} -o $(NAME) .

.PHONY: static
static: ## Builds a static executable.
	@echo "+ $@"
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build \
				-tags "$(BUILDTAGS) static_build" \
				${GO_LDFLAGS_STATIC} -o $(NAME) .

all: clean build fmt lint test staticcheck vet

.PHONY: fmt
fmt: ## Verifies all files have been `gofmt`ed.
	@echo "+ $@"
	@gofmt -s -l . | grep -v '.pb.go:' | grep -v vendor | tee /dev/stderr

.PHONY: lint
lint: ## Verifies `golint` passes.
	@echo "+ $@"
	@golint ./... | grep -v '.pb.go:' | grep -v vendor | tee /dev/stderr

.PHONY: test
test: ## Runs the go tests.
	@echo "+ $@"
	@$(GO) test -v -tags "$(BUILDTAGS) cgo" $(shell $(GO) list ./... | grep -v vendor)

.PHONY: vet
vet: ## Verifies `go vet` passes.
	@echo "+ $@"
	@$(GO) vet $(shell $(GO) list ./... | grep -v vendor) | grep -v '.pb.go:' | tee /dev/stderr

.PHONY: staticcheck
staticcheck: ## Verifies `staticcheck` passes.
	@echo "+ $@"
	@staticcheck $(shell $(GO) list ./... | grep -v vendor) | grep -v '.pb.go:' | tee /dev/stderr

.PHONY: cover
cover: ## Runs go test with coverage.
	@echo "" > coverage.txt
	@for d in $(shell $(GO) list ./... | grep -v vendor); do \
		$(GO) test -race -coverprofile=profile.out -covermode=atomic "$$d"; \
		if [ -f profile.out ]; then \
			cat profile.out >> coverage.txt; \
			rm profile.out; \
		fi; \
	done;

define buildrelease
GOOS=$(1) GOARCH=$(2) CGO_ENABLED=$(CGO_ENABLED) $(GO) build \
	 -o $(BUILDDIR)/$(NAME)-$(1)-$(2) \
	 -a -tags "$(BUILDTAGS) static_build netgo" \
	 -installsuffix netgo ${GO_LDFLAGS_STATIC} .;
endef

# md5sum $(BUILDDIR)/$(NAME)-$(1)-$(2) > $(BUILDDIR)/$(NAME)-$(1)-$(2).md5;
# sha256sum $(BUILDDIR)/$(NAME)-$(1)-$(2) > $(BUILDDIR)/$(NAME)-$(1)-$(2).sha256;

.PHONY: release
release: *.go
	@echo "+ $@"
	$(foreach GOOSARCH,$(GOOSARCHES), $(call buildrelease,$(subst /,,$(dir $(GOOSARCH))),$(notdir $(GOOSARCH))))

.PHONY: AUTHORS
AUTHORS:
	@$(file >$@,# This file lists all individuals having contributed content to the repository.)
	@$(file >>$@,# For how it is generated, see `make AUTHORS`.)
	@echo "$(shell git log --format='\n%aN <%aE>' | LC_ALL=C.UTF-8 sort -uf)" >> $@

.PHONY: clean
clean: ## Cleanup any build binaries or packages.
	@echo "+ $@"
	$(RM) $(NAME)
	$(RM) -r $(BUILDDIR)

