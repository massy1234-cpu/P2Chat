proto:
	protoc --go_out=. --go_opt=module=P2Chat cmd/client/internals/proto/commitment/*.proto
	protoc --go_out=. --go_opt=module=P2Chat cmd/client/internals/proto/login/*.proto
	protoc --go_out=. --go_opt=module=P2Chat cmd/client/internals/proto/server_identification/*.proto
	protoc --go_out=. --go_opt=module=P2Chat cmd/client/internals/proto/mldsa/*.proto cmd/client/internals/proto/PoW/*.proto cmd/client/internals/proto/argon/*.proto cmd/client/internals/proto/pqxdh/*.proto cmd/client/internals/proto/x25519/*.proto cmd/server/internals/proto/identity/*.proto cmd/server/internals/proto/pqxdh/*.proto cmd/server/internals/proto/PoW/*.proto

run: proto
	cd cmd/client && go run .

run-server:
	cd cmd/server && go run .
