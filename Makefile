proto:
	protoc --go_out=. cmd/client/internals/mldsa/proto/*.proto

run: proto
	cd cmd/client && go run .
