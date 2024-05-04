 .PHONY: client
client:
	go run client/client.go

 .PHONY: counter
counter:
	go run counter/counter.go

 .PHONY: registrar
registrar:
	go run registrar/registrar.go