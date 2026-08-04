proto:
	protoc --go_out=. --go_opt=module=P2Chat cmd/client/internals/proto/mldsa/*.proto cmd/client/internals/proto/PoW/*.proto cmd/client/internals/proto/argon/*.proto

run: proto
	cd cmd/client && go run .

run-server:
	cd cmd/server && go run .
