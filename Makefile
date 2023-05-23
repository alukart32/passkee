pg_name = postgres14
pg_user = postgres
pg_user_pass = postgres
pg_image = postgres:14-alpine
pg_uri = localhost:5432
db_name = passkee


.PHONY: help
help:
	@echo List of params:
	@echo   db_name                 - postgres docker container name (default: $(pg_name))
	@echo   pq_user                 - postgres root user (default: $(pg_user))
	@echo   pq_user_pass            - postgres root user password (default: $(pg_user_pass))
	@echo   db_image                - postgres docker image (default: $(pg_image))
	@echo   db_uri                  - postgres uri (default: $(pg_uri))
	@echo   db_name                 - postgres main db (default: $(db_name))
	@echo List of commands:
	@echo   postgres-up             - run postgres postgres docker container $(pg_name)
	@echo   postgres-up             - down postgres postgres docker container $(pg_name)
	@echo   create-db               - create db $(db_name)
	@echo   drop-db                 - drop db $(db_name)
	@echo   test                    - run all tests
	@echo   test-cover              - show test coverage
	@echo   gen                     - gen resources
	@echo   help                    - help info
	@echo   clear                   - truncate resources
	@echo Usage:
	@echo                           make `cmd_name`

.PHONY: postgres-up
postgres-up:
	docker run --name $(pg_name) -e POSTGRES_USER=$(pg_user) -e POSTGRES_PASSWORD=$(pg_user_pass) -p 5432:5432 -d $(pg_image)

.PHONY: postgres-stop
postgres-stop:
	docker stop $(pg_name)

.PHONY: create-db
create-db:
	docker exec -it $(pg_name) createdb --username=$(pg_user) --owner=$(pg_user) $(db_name)

.PHONY: drop-db
drop-db:
	docker exec -it $(pg_name) dropdb --username=$(pg_user) $(db_name)

.PHONY: test
test:
	go test ./internal/... -coverprofile cover.out

.PHONY: test-cover
test-cover: test
	go tool cover -func cover.out

.PHONY: go-gen
go-gen:
	go generate ./...

.PHONY: grpc-gen-v1
grpc-gen-v1:
	protoc --go_out=. --go_opt=paths=import \
	--go-grpc_out=. --go-grpc_opt=paths=import \
	--proto_path=api/v1/proto/ \
	--proto_path="${PROTO_PATH}" \
	auth.proto \
	object.proto \
	credit_card.proto \
	passwords.proto

.PHONY: docker-clear
docker-clear: drop-db postgres-stop
	docker rm $(pg_name)

.PHONY: run-with-db
run-with-db:
	go run ./cmd/vault/main.go -a "localhost:50052" -v "Zuy4B2CiHyYKtaoCV9clnuMdi7eV3cOi" -d "postgres://$(pg_user):$(pg_user_pass)@localhost:5432/$(db_name)"

.PHONY: run-with-config
run-with-config:
	go run ./cmd/vault/main.go -c "./configs/config.json"

.PHONY: build-cli
build-cli:
	go build -C ./cmd/cli/ -ldflags \
	"-X github.com/alukart32/yandex/practicum/passkee/internal/cli/cmd.Version=v1.0.0 \
	-X 'github.com/alukart32/yandex/practicum/passkee/internal/cli/cmd.BuildTime=$(date +'%Y/%m/%d %H:%M:%S')'"

.PHONY: test
test:
	go test ./internal/... -coverprofile cover.out

.PHONY: test-cover
test-cover: test
	go tool cover -func cover.out
