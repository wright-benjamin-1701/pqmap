FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /app main.go

FROM alpine:3.19
COPY --from=build /app /app
EXPOSE 8443 50051
CMD ["/app"]
