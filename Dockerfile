FROM golang:latest

# NOTE: It is expected from you to build the binary beforehand
COPY map /usr/bin/exporter

ENTRYPOINT [ "/usr/bin/exporter" ]
