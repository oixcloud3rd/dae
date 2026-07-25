#
#  SPDX-License-Identifier: AGPL-3.0-only
#  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
#

OIXCLOUD_DNS_AUTH_PRIVATE_KEY_FROM_ENV := $(OIXCLOUD_DNS_AUTH_PRIVATE_KEY)
OIXCLOUD_SUBSCRIPTION_HMAC_KEY_FROM_ENV := $(OIXCLOUD_SUBSCRIPTION_HMAC_KEY)
-include .env
ifneq ($(strip $(OIXCLOUD_DNS_AUTH_PRIVATE_KEY_FROM_ENV)),)
OIXCLOUD_DNS_AUTH_PRIVATE_KEY := $(OIXCLOUD_DNS_AUTH_PRIVATE_KEY_FROM_ENV)
endif
ifneq ($(strip $(OIXCLOUD_SUBSCRIPTION_HMAC_KEY_FROM_ENV)),)
OIXCLOUD_SUBSCRIPTION_HMAC_KEY := $(OIXCLOUD_SUBSCRIPTION_HMAC_KEY_FROM_ENV)
endif

# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang
STRIP ?= llvm-strip
CFLAGS := -O2 -Wall -Werror $(CFLAGS)
TARGET ?= bpfel,bpfeb
OUTPUT ?= dae
MAX_MATCH_SET_LEN ?= 1024
CFLAGS := -DMAX_MATCH_SET_LEN=$(MAX_MATCH_SET_LEN) $(CFLAGS)
DEFAULT_GOEXPERIMENT := heapminimum512kib,randomizedheapbase64
GOEXPERIMENT_MERGED := $(shell printf '%s\n' "$(DEFAULT_GOEXPERIMENT),$(GOEXPERIMENT)" | tr ',' '\n' | sed '/^$$/d' | awk '!seen[$$0]++' | paste -sd, -)
export GOEXPERIMENT := $(GOEXPERIMENT_MERGED)
# Host-side helper programs must not inherit target runtime experiments. In
# particular, an older bootstrap cmd/go may need to select a newer toolchain
# before it can parse those experiments.
GO ?= go
HOST_GO_ENV := env -u GOOS -u GOARCH -u GOARM -u GOAMD64 -u GORISCV64 -u GOEXPERIMENT -u GOFIPS140
GO_TOOL := $(shell $(HOST_GO_ENV) $(GO) env GOROOT)/bin/go
# Resolve the module-selected toolchain once without experiments, then invoke
# it directly. This prevents every make subtarget from re-entering bootstrap
# toolchain selection with target-only GOEXPERIMENT values in its environment.
TARGET_GO := env GOTOOLCHAIN=local $(GO_TOOL)
HOST_GO := $(HOST_GO_ENV) GOTOOLCHAIN=local CGO_ENABLED=0 $(GO_TOOL)
NOSTRIP ?= n
STRIP_PATH := $(shell command -v $(STRIP) 2>/dev/null)
BUILD_TAGS_FILE := .build_tags
ifeq ($(strip $(NOSTRIP)),y)
	STRIP_FLAG := -no-strip
else ifeq ($(wildcard $(STRIP_PATH)),)
	STRIP_FLAG := -no-strip
else
	STRIP_FLAG := -strip=$(STRIP_PATH)
endif

GOARCH ?= $(shell $(HOST_GO) env GOARCH)

# Do NOT remove the line below. This line is for CI.
#export GOMODCACHE=$(PWD)/go-mod

# Get version from .git.
date=$(shell git log -1 --format="%cd" --date=short | sed s/-//g)
count=$(shell git rev-list --count HEAD)
commit=$(shell git rev-parse --short HEAD)
ifeq ($(wildcard .git/.),)
	VERSION ?= unstable-0.nogit
else
	VERSION ?= unstable-$(date).r$(count).$(commit)
endif

OIXCLOUD_DNS_AUTH_PRIVATE_KEY ?=
export OIXCLOUD_DNS_AUTH_PRIVATE_KEY
OIXCLOUD_DNS_AUTH_LDFLAGS = $(if $(strip $(OIXCLOUD_DNS_AUTH_PRIVATE_KEY)),-X 'github.com/daeuniverse/dae/common/consts.OIXCloudDNSAuthPrivateKey=$(OIXCLOUD_DNS_AUTH_PRIVATE_KEY)')
OIXCLOUD_SUBSCRIPTION_HMAC_KEY ?=
export OIXCLOUD_SUBSCRIPTION_HMAC_KEY
OIXCLOUD_SUBSCRIPTION_LDFLAGS = $(if $(strip $(OIXCLOUD_SUBSCRIPTION_HMAC_KEY)),-X 'github.com/daeuniverse/dae/common/consts.OIXCloudSubscriptionHMACKey=$(OIXCLOUD_SUBSCRIPTION_HMAC_KEY)')
BUILD_ARGS := -trimpath -ldflags "-s -w -X github.com/daeuniverse/dae/cmd.Version=$(VERSION) -X github.com/daeuniverse/dae/common/consts.MaxMatchSetLen_=$(MAX_MATCH_SET_LEN) $(OIXCLOUD_DNS_AUTH_LDFLAGS) $(OIXCLOUD_SUBSCRIPTION_LDFLAGS)" $(BUILD_ARGS)

.PHONY: clean-ebpf ebpf ebpf-sync ebpf-sync-check ebpf-test-tagged ebpf-test-debug ebpf-test-debug-tagged ebpf-audit dae validate-oixcloud-dns-auth-private-key validate-oixcloud-subscription-hmac-key submodule submodules

## Begin Dae Build
dae: export GOOS=linux
ifndef CGO_ENABLED
dae: export CGO_ENABLED=0
endif
dae: validate-oixcloud-dns-auth-private-key validate-oixcloud-subscription-hmac-key ebpf
	@echo $(CFLAGS)
	@$(TARGET_GO) build -tags=$(shell cat $(BUILD_TAGS_FILE)) -o $(OUTPUT) $(BUILD_ARGS) .
## End Dae Build

validate-oixcloud-dns-auth-private-key:
	@$(HOST_GO) run ./cmd/internal/check_oixcloud_dns_auth_key

validate-oixcloud-subscription-hmac-key:
	@$(HOST_GO) run ./cmd/internal/check_oixcloud_subscription_hmac_key

## Begin Git Submodules
.gitmodules.d.mk: .gitmodules
	@set -e && \
	submodules=$$(grep '\[submodule "' .gitmodules | cut -d'"' -f2 | tr '\n' ' ' | tr ' \n' '\n') && \
	echo "submodule_paths=$${submodules}" > $@

-include .gitmodules.d.mk

$(submodule_paths): .gitmodules.d.mk
	git submodule update --init --recursive -- $@ && \
	touch $@

submodule submodules: $(submodule_paths)
	@if [ -z "$(submodule_paths)" ]; then \
		rm -f .gitmodules.d.mk; \
		echo "Failed to generate submodules list. Please try again."; \
		exit 1; \
	fi
## End Git Submodules

## Begin Ebpf
clean-ebpf:
	@rm -f control/bpf_bpf*.go && \
			rm -f control/bpf_bpf*.o
	@rm -f control/bpftest_bpf*.go && \
			rm -f control/bpftest_bpf*.o
	@rm -f trace/bpf_*_bpf*.go && \
			rm -f trace/bpf_*_bpf*.o
	@rm -f control/kern/tests/bpftest_bpf*.go && \
			rm -f control/kern/tests/bpftest_bpf*.o
fmt:
	$(TARGET_GO) fmt ./...

ebpf-sync:
	@unset GOOS && \
	unset GOARCH && \
	unset GOARM && \
	unset GOAMD64 && \
	$(TARGET_GO) generate ./common/consts/ebpf.go

ebpf-sync-check: ebpf-sync
	git diff --exit-code -- common/consts/ebpf_generated.go control/kern/ebpf_sync_defs.h

# $BPF_CLANG is used in go:generate invocations.
ebpf: export BPF_CLANG := $(CLANG)
ebpf: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf: export BPF_CFLAGS := $(CFLAGS)
ebpf: export BPF_TARGET := $(TARGET)
ebpf: export BPF_TRACE_TARGET := $(GOARCH)
ebpf: ebpf-sync submodule clean-ebpf
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    $(TARGET_GO) generate ./control/control.go && \
	if $(TARGET_GO) generate ./trace/trace.go; then \
		echo trace > $(BUILD_TAGS_FILE); \
	else \
		echo > $(BUILD_TAGS_FILE); \
	fi

ebpf-lint:
	./scripts/checkpatch.pl --no-tree --strict --no-summary --show-types --color=always control/kern/tproxy.c --ignore COMMIT_COMMENT_SYMBOL,NOT_UNIFIED_DIFF,COMMIT_LOG_LONG_LINE,LONG_LINE_COMMENT,VOLATILE,ASSIGN_IN_IF,PREFER_DEFINED_ATTRIBUTE_MACRO,CAMELCASE,LEADING_SPACE,OPEN_ENDED_LINE,SPACING,BLOCK_COMMENT_STYLE

ebpf-test: export BPF_CLANG := $(CLANG)
ebpf-test: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test: export BPF_CFLAGS := $(CFLAGS)
ebpf-test: export BPF_TARGET := $(TARGET)
ebpf-test: export BPF_TRACE_TARGET := $(GOARCH)
ebpf-test: ebpf-sync submodule clean-ebpf
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    $(TARGET_GO) generate ./control/bpf_bug_verification_test.go && \
    $(TARGET_GO) generate ./control/kern/tests/bpf_test.go && \
    $(TARGET_GO) clean -testcache && \
    $(TARGET_GO) test -v -tags dae_bpf_tests ./control/kern/tests/...

ebpf-test-tagged: export BPF_CLANG := $(CLANG)
ebpf-test-tagged: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test-tagged: export BPF_CFLAGS := $(CFLAGS)
ebpf-test-tagged: export BPF_TARGET := $(TARGET)
ebpf-test-tagged: export BPF_TRACE_TARGET := $(GOARCH)
ebpf-test-tagged: ebpf-sync submodule clean-ebpf
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    $(TARGET_GO) generate ./control/bpf_bug_verification_test.go && \
    $(TARGET_GO) generate ./control/kern/tests/bpf_test.go && \
    $(TARGET_GO) clean -testcache && \
    $(TARGET_GO) test -v -tags dae_bpf_tests ./control/kern/tests/...

ebpf-test-debug: export BPF_CLANG := $(CLANG)
ebpf-test-debug: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test-debug: export BPF_CFLAGS := $(CFLAGS) -D__BPF_TEST_ENABLE_DEBUG
ebpf-test-debug: export BPF_TARGET := $(TARGET)
ebpf-test-debug: export BPF_TRACE_TARGET := $(GOARCH)
ebpf-test-debug: ebpf-sync submodule clean-ebpf
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    $(TARGET_GO) generate ./control/bpf_bug_verification_test.go && \
    $(TARGET_GO) generate ./control/kern/tests/bpf_test.go && \
    $(TARGET_GO) clean -testcache && \
    $(TARGET_GO) test -v -tags dae_bpf_tests ./control/kern/tests/...

ebpf-test-debug-tagged: export BPF_CLANG := $(CLANG)
ebpf-test-debug-tagged: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test-debug-tagged: export BPF_CFLAGS := $(CFLAGS) -D__BPF_TEST_ENABLE_DEBUG
ebpf-test-debug-tagged: export BPF_TARGET := $(TARGET)
ebpf-test-debug-tagged: export BPF_TRACE_TARGET := $(GOARCH)
ebpf-test-debug-tagged: ebpf-sync submodule clean-ebpf
	@unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    $(TARGET_GO) generate ./control/bpf_bug_verification_test.go && \
    $(TARGET_GO) generate ./control/kern/tests/bpf_test.go && \
    $(TARGET_GO) clean -testcache && \
    $(TARGET_GO) test -v -tags dae_bpf_tests ./control/kern/tests/...

ebpf-audit:
	./scripts/ebpf-audit.sh

## End Ebpf
