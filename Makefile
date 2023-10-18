cert:
	./scripts/makecert

up:
	docker-compose up -d

test:
	./scripts/test apple.example.com
	./scripts/test banana.example.com

down:
	docker-compose down

clean:
	find certs -type f | grep -v ".json" | xargs rm

.PHONY: cert up down test clean
