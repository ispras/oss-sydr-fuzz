#!/bin/bash

# Собираем фаззер
go-fuzz-build -o fuzz-parsefile.zip github.com/ollama/ollama/parser

# Собираем Sydr-цель (если нужно)
go build -o sydr-parsefile ./sydr_parsefile.go
