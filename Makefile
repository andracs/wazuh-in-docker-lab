# Wazuh Security Lab - make targets wrap ./lab.sh
.DEFAULT_GOAL := help

.PHONY: help up down status scenarios reset verify test logs

help:
	@echo "Targets: make up | down | status | scenario-<name> | verify | test"
	@echo "Scenarios: normal, misconfiguration, web-attack, compromised-client"

up:
	./lab.sh up

down:
	./lab.sh down

status:
	./lab.sh status

scenario-normal:
	./lab.sh scenario normal

scenario-misconfiguration:
	./lab.sh scenario misconfiguration

scenario-web-attack:
	./lab.sh scenario web-attack

scenario-compromised-client:
	./lab.sh scenario compromised-client

verify:
	./lab.sh verify

test:
	./lab.sh test

logs:
	./lab.sh logs
