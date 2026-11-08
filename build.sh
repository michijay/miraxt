
SOURCE="cli.go"
SOURCE2="gui.go"
PROGNAME="miraxt"

rm -v miraxt*

go build -o $PROGNAME-linux-cli-amd64 $SOURCE
GOOS=windows GOARCH=amd64 go build -o $PROGNAME-windows-cli-amd64.exe $SOURCE
GOOS=darwin GOARCH=arm64 go build -o $PROGNAME-mac-cli-arm64 $SOURCE
GOOS=darwin GOARCH=amd64 go build -o $PROGNAME-mac-cli-amd64 $SOURCE

go build -o $PROGNAME-linux-amd64 $SOURCE2
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -v -o $PROGNAME-windows-amd64.exe $SOURCE2
