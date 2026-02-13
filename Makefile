.PHONY: up down logs test

up:
	docker compose up -d --build --remove-orphans

down:
	docker compose down -v --remove-orphans

logs:
	docker compose logs -f --tail=200

test:
	curl -s "http://localhost:8080/check?zone=example.com" | python -c 'import sys,json; d=json.load(sys.stdin); print(d["summary"])'
