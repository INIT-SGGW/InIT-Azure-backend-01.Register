FROM golang:1.23.5-alpine

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN cd server && go build -o /app/01register-server
EXPOSE 3131
CMD ["/app/01register-server"]