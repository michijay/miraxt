
SOURCE="cli.go"
PROGNAME="miraxt-cli"

go build -o $PROGNAME-linux-amd64 $SOURCE
GOOS=windows GOARCH=amd64 go build -o $PROGNAME-windows-amd64.exe $SOURCE
GOOS=darwin GOARCH=arm64 go build -o $PROGNAME-mac-arm64 $SOURCE
GOOS=darwin GOARCH=amd64 go build -o $PROGNAME-mac-amd64 $SOURCE
