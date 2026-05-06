proto:
	protoc --go_out=. --go_opt=module=P2Chat cmd/client/internals/proto/mldsa/*.proto

run: proto
	cd cmd/client && go run .
