all: config.pb.go

%.pb.go: %.proto
		protoc --go_out=plugins=grpc:. --go_opt=paths=source_relative $?
