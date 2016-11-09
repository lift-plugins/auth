BRANCH		:= $(shell git rev-parse --abbrev-ref HEAD)
LDFLAGS 	:= -ldflags "-X main.Version=$(VERSION) -X main.Name=$(NAME)"

test:
	go test ./...

build:
	go build -o $(NAME) $(LDFLAGS) cmd/$(NAME)/$(NAME).go

install:
	go install $(LDFLAGS) cmd/$(NAME).go

compile:
	@rm -rf build/
	@gox $(LDFLAGS) \
	-osarch="darwin/amd64 darwin/386" \
	-osarch="windows/amd64 windows/386" \
	-osarch="freebsd/386 freebsd/amd64 freebsd/arm freebsd/arm64" \
	-osarch="linux/amd64 linux/386 linux/arm linux/arm64" \
	-osarch="solaris/amd64" \
	-output "build/$(NAME)_$(VERSION)_{{.OS}}_{{.Arch}}/$(NAME)" \
	./...

dist: compile
	$(eval FILES := $(shell ls build))
	@rm -rf dist && mkdir dist
	@for f in $(FILES); do \
		(cd $(shell pwd)/build/$$f && tar -cvzf ../../dist/$$f.tar.gz *); \
		(cd $(shell pwd)/dist && shasum -a 512 $$f.tar.gz > $$f.sha512); \
		echo $$f; \
	done

release: dist
	@latest_tag=$$(git describe --tags `git rev-list --tags --max-count=1`); \
	comparison="$$latest_tag..HEAD"; \
	if [ -z "$$latest_tag" ]; then comparison=""; fi; \
	changelog=$$(git log $$comparison --oneline --no-merges --reverse); \
	github-release $(GHACCOUNT)/$(NAME) $(VERSION) $(BRANCH) "**Changelog**<br/>$$changelog" 'dist/*'; \
	git pull

.PHONY: test build install compile dist release
