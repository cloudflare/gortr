EXTENSION ?= 
DIST_DIR ?= dist/
GOOS ?= linux
ARCH ?= $(shell uname -m)
BUILDINFOSDET ?= 

DOCKER_REPO   := cloudflare/
GORTR_NAME    := gortr
GORTR_VERSION := $(shell git describe --tags $(git rev-list --tags --max-count=1))
VERSION_PKG   := $(shell echo $(GORTR_VERSION) | sed 's/^v//g')
ARCH          := x86_64
LICENSE       := BSD-3
URL           := https://github.com/cloudflare/gortr
DESCRIPTION   := GoRTR: a RPKI-to-Router server
BUILDINFOS    :=  ($(shell date +%FT%T%z)$(BUILDINFOSDET))
LDFLAGS       := '-X main.version=$(GORTR_VERSION) -X main.buildinfos=$(BUILDINFOS)'

RTRDUMP_NAME        := rtrdump

OUTPUT_GORTR := $(DIST_DIR)gortr-$(GORTR_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)
OUTPUT_RTRDUMP := $(DIST_DIR)rtrdump-$(GORTR_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)

.PHONY: vet
vet:
	go vet cmd/gortr/gortr.go

.PHONY: test
test:
	go test -v github.com/cloudflare/gortr/lib
	go test -v github.com/cloudflare/gortr/prefixfile

.PHONY: prepare
prepare:
	mkdir -p $(DIST_DIR)

.PHONY: clean
clean:
	rm -rf $(DIST_DIR)

.PHONY: dist-key
dist-key: prepare
	cp cmd/gortr/cf.pub $(DIST_DIR)

.PHONY: build-gortr
build-gortr: prepare
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_GORTR) cmd/gortr/gortr.go 

.PHONY: build-rtrdump
build-rtrdump:
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_RTRDUMP) cmd/rtrdump/rtrdump.go 

.PHONY: docker-gortr
docker-gortr:
	docker build -t $(DOCKER_REPO)$(GORTR_NAME):$(GORTR_VERSION) --build-arg LDFLAGS=$(LDFLAGS) -f Dockerfile.gortr .

.PHONY: docker-rtrdump
docker-rtrdump:
	docker build -t $(DOCKER_REPO)$(RTRDUMP_NAME):$(GORTR_VERSION) --build-arg LDFLAGS=$(LDFLAGS) -f Dockerfile.rtrdump .

.PHONY: package-deb-gortr
package-deb-gortr: prepare
	fpm -s dir -t deb -n $(GORTR_NAME) -v $(VERSION_PKG) \
        --description "$(DESCRIPTION)"  \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE)" \
        --package $(DIST_DIR) \
        $(OUTPUT_GORTR)=/usr/bin/gortr \
        package/gortr.service=/lib/systemd/system/gortr.service \
        package/gortr.env=/etc/default/gortr \
        cmd/gortr/cf.pub=/usr/share/gortr/cf.pub \
        $(OUTPUT_RTRDUMP)=/usr/bin/rtrdump

.PHONY: package-rpm-gortr
package-rpm-gortr: prepare
	fpm -s dir -t rpm -n $(GORTR_NAME) -v $(VERSION_PKG) \
        --description "$(DESCRIPTION)" \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE) "\
        --package $(DIST_DIR) \
        $(OUTPUT_GORTR)=/usr/bin/gortr \
        package/gortr.service=/lib/systemd/system/gortr.service \
        package/gortr.env=/etc/default/gortr \
        cmd/gortr/cf.pub=/usr/share/gortr/cf.pub \
        $(OUTPUT_RTRDUMP)=/usr/bin/rtrdump
