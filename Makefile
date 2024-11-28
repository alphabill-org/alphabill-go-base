all: tools test gosec

build:
	go build ./...

test:
	go test ./... -coverpkg=./... -count=1 -coverprofile test-coverage.out

gosec:
	gosec -fmt=sonarqube -out gosec_report.json -no-fail ./...

tools:
	go install github.com/securego/gosec/v2/cmd/gosec@latest

.PHONY: \
	all \
	build \
	tools \
	test \
	gosec
