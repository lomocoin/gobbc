fmt:
	go fmt ./...
	cd qa && go fmt 

test:
	go test

qaTest:
	cd qa && go test

all: fmt test qaTest