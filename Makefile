proto:
	protoc --go_out=. cmd/client/internals/proto/*.proto

run: proto
	cd cmd/client && go run .
