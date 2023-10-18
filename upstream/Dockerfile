FROM golang:1.21.0

WORKDIR /app

COPY . /app
RUN go build main.go

EXPOSE 8080

CMD [ "/app/main" ]