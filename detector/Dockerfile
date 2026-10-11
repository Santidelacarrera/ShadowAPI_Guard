FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -o /detector ./cmd/detector

FROM alpine:3.20
RUN adduser -D -u 10001 app
COPY --from=build /detector /detector
USER app
EXPOSE 8081
ENTRYPOINT ["/detector"]
