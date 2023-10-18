FROM golang:1.21.0

WORKDIR /app

COPY . /app
RUN go get && cd main && go build main.go

EXPOSE 18000

CMD [ "/app/main/main" ]