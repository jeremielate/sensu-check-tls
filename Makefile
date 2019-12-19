
ARCHIVE_NAME="ctp-sensu-check-tls.tar.gz"

build:
	mkdir -p ./bin ./lib ./include
	go build -o ./bin

archive: build
	tar --owner=0 --group=0 -pcvzf ${ARCHIVE_NAME} ./bin ./lib ./include

archive-checksum: archive
	sha512sum ${ARCHIVE_NAME} > sha512sum.txt
	sha256sum ${ARCHIVE_NAME} > sha256sum.txt

clean:
	rm -r ./bin ./lib ./include
