TARGET=kube-auth-tools

$(TARGET): main.go connector/dex.go cmd/login.go cmd/root.go cmd/update.go
	go build -v -o "$@"

.PHONY: build
build: $(TARGET)

.PHONY: clean
clean:
	-rm $(TARGET)
