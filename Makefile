.PHONY: help
help:
	@grep -E '^[a-zA-Z0-9_-]+%?:.*?## .*$$' $(MAKEFILE_LIST) | sed -e 's/^Makefile://' | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

mac_services_listening: ## display listening processes and what port
	@lsof -i -P | grep LISTEN

go_tests: ## runs all go tests
	go test -v ./...

run: ## start oauth2 server
	@go run main.go

local_token_test:
	curl -X POST -d "client_id=test_client&client_secret=test_secret&grant_type=client_credentials&scope=read" http://localhost:9096/token

local_protected_test:
	curl -H "Authorization: Bearer NZAWMMFIZGUTNMUXMC0ZY2YYLTG2ZDATZJDLNDZLMWYWYJLK" http://localhost:9096/protected