BINARY    := bin/olaitan
MODULE    := github.com/olokotoh/olaitan
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -ldflags "-X main.version=$(VERSION)"
IMAGE     := olaitan
TAG       ?= $(VERSION)

.PHONY: build test lint docker-build clean

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/olaitan

test:
	go test ./... -v -count=1

lint:
	golangci-lint run ./...

docker-build:
	docker build -t $(IMAGE):$(TAG) .

clean:
	rm -rf bin/
