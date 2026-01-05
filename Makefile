SHELL := /bin/bash

IMAGE_NAME ?= pqc-quic-benchmark-3.6
DOCKER ?= docker
MODE ?= all
KEM ?=
SIG ?=
COUNT ?= 50
QUIC_MODE ?= 0
LOSS_PROFILE ?= 0
NETEM_INTERFACE ?= lo
ACK_PAD ?= OFF
DEBUG_LOG ?= OFF
MEASURE_ONLY ?= OFF
PRINT_MODE ?=
PIN_SERVER_CPU ?=
PIN_CLIENT_CPU ?=
HOST_TUNING ?= on
HOST_TUNING_AUTO_CPU_COUNT ?= 2
HOST_TUNING_SKIP_CPUS ?= 0
HOST_TUNING_STATE_DIR ?= $(CURDIR)/.host_tuning_state
HOST_TUNING_STATE_DIR_ABS := $(abspath $(HOST_TUNING_STATE_DIR))
HOST_TUNING_CPUS ?= $(shell HOST_TUNING_SKIP_CPUS=$(HOST_TUNING_SKIP_CPUS) scripts/select_physical_cpus.py $(HOST_TUNING_AUTO_CPU_COUNT))
HOST_TUNING_GOVERNOR ?= performance
HOST_TUNING_DISABLE_BOOST ?= on
MERMAID_CLI_IMAGE ?= minlag/mermaid-cli:latest
HOST_TUNING_SCRIPT := $(CURDIR)/scripts/with_host_tuning.sh
HOST_TUNING_STATUS_SCRIPT := $(CURDIR)/scripts/host_tuning_status.sh

ifneq ($(strip $(value ACK-PAD)),)
override ACK_PAD := $(value ACK-PAD)
endif
RESULTS_DIR ?= $(CURDIR)/results
HOST_UID := $(shell id -u 2>/dev/null || echo 0)
HOST_GID := $(shell id -g 2>/dev/null || echo 0)

ifneq ($(strip $(mode)),)
override MODE := $(mode)
endif
ifneq ($(strip $(kem)),)
override KEM := $(kem)
endif
ifneq ($(strip $(sig)),)
override SIG := $(sig)
endif
ifneq ($(strip $(count)),)
override COUNT := $(count)
endif
ifneq ($(strip $(loss_profile)),)
override LOSS_PROFILE := $(loss_profile)
endif
ifneq ($(strip $(quic_mode)),)
override QUIC_MODE := $(quic_mode)
endif
ifneq ($(strip $(netem_interface)),)
override NETEM_INTERFACE := $(netem_interface)
endif

.PHONY: build run packetCount diagram clean kem-sig help host-status

help:
	@echo "Available make targets:"
	@echo "  build        Build the Docker image ($(IMAGE_NAME))."
	@echo "  run          Run the benchmark suite inside the Docker container."
	@echo "  packetCount  Run the packet count benchmark variant."
	@echo "  diagram      Build a Mermaid packet-flow diagram using the latest packet-mode run (auto-runs if missing)."
	@echo "  host-status  Show current host tuning status (governor, boost, cset)."
	@echo "  kem-sig      List supported KEM and signature combinations."
	@echo "  clean        Remove generated benchmark results."
	@echo ""
	@echo "Configurable variables (override with 'make <target> VAR=value'):"
	@echo "  MODE                Benchmark mode: all, pqc, hybrid, or one (default: $(MODE))."
	@echo "  KEM                 KEM algorithm when MODE=one. See 'make kem-sig' (default: \"$(KEM)\")."
	@echo "  SIG                 Signature algorithm when MODE=one. See 'make kem-sig' (default: \"$(SIG)\")."
	@echo "  COUNT               Number of runs per combination; positive integer (default: $(COUNT))."
	@echo "  QUIC_MODE           PQC QUIC mode: 0 (QUIC Default - RFC 9000), 1 (Amplification OFF - No Address Validation), 2 (QUIC Default + ACK-Padding), 3 (QUIC Default + Adaptive ACK-Padding) (default: $(QUIC_MODE))."
	@echo "  LOSS_PROFILE        Network loss profile: 0, 0.1, 0.5, 1, 2, 5, 10, 15, 20, 25, 30, bursty (default: $(LOSS_PROFILE))."
	@echo "  NETEM_INTERFACE     Interface for tc netem (default: $(NETEM_INTERFACE))."
	@echo "  RESULTS_DIR         Directory for storing benchmark results (default: $(RESULTS_DIR))."
	@echo "  PRINT_MODE          Output detail level: benchmark, debug, packet (default: benchmark)."
	@echo "  DEBUG_LOG           When 'ON', enable verbose server/client logging (--debug) (default: $(DEBUG_LOG))."
	@echo "  MEASURE_ONLY        When 'ON', disable client certificate verification/logging to focus on RTT (default: $(MEASURE_ONLY))."
	@echo "  PIN_SERVER_CPU      Host logical CPU to pin the QUIC server (default: auto)."
	@echo "  PIN_CLIENT_CPU      Host logical CPU to pin the QUIC client (default: auto)."
	@echo "  HOST_TUNING         When 'on', apply host governor/Turbo/CPU shielding before running (default: $(HOST_TUNING))."
	@echo "  HOST_TUNING_CPUS    Comma-separated CPUs reserved for the benchmark when HOST_TUNING=on (default: \"$(HOST_TUNING_CPUS)\")."
	@echo "  HOST_TUNING_SKIP_CPUS CPUs to deprioritize during auto-selection (default: $(HOST_TUNING_SKIP_CPUS))."
	@echo "  HOST_TUNING_GOVERNOR CPU governor to apply when HOST_TUNING=on (default: $(HOST_TUNING_GOVERNOR))."
	@echo "  HOST_TUNING_DISABLE_BOOST Disable Turbo when HOST_TUNING=on (on/off, default: $(HOST_TUNING_DISABLE_BOOST))."
	@echo "  HOST_TUNING_CPUS         CPUs to show in 'make host-status' (default: $(HOST_TUNING_CPUS))."
	@echo "  DOCKER              Docker command or alternative runtime (default: $(DOCKER))."
	@echo "  IMAGE_NAME          Name for the built Docker image (default: $(IMAGE_NAME))."

build:
	$(DOCKER) build --pull --no-cache -t $(IMAGE_NAME) .
	@$(DOCKER) builder prune -f >/dev/null 2>&1 || true
	@$(DOCKER) image prune -f >/dev/null 2>&1 || true

kem-sig:
	@if ! $(DOCKER) image inspect $(IMAGE_NAME) >/dev/null 2>&1; then \
		echo "Docker image '$(IMAGE_NAME)' not found. Run 'make build' first."; \
		exit 1; \
	fi
	@if [ ! -f scripts/list_kem_sig.py ]; then \
		echo "scripts/list_kem_sig.py not found on host. Create it first."; \
		exit 1; \
	fi
	@$(DOCKER) run --rm --entrypoint python3 -v $(CURDIR)/scripts:/ext_scripts:ro \
		$(IMAGE_NAME) /ext_scripts/list_kem_sig.py

run:
	@if ! $(DOCKER) image inspect $(IMAGE_NAME) >/dev/null 2>&1; then \
		echo "Docker image '$(IMAGE_NAME)' not found. Run 'make build' before 'make run'."; \
		exit 1; \
	fi
	mkdir -p $(RESULTS_DIR)
	$(if $(filter on,$(HOST_TUNING)),PIN_SERVER_CPU=$(PIN_SERVER_CPU) PIN_CLIENT_CPU=$(PIN_CLIENT_CPU) HOST_TUNING_STATE_DIR=$(HOST_TUNING_STATE_DIR_ABS) $(HOST_TUNING_SCRIPT) $(if $(strip $(HOST_TUNING_CPUS)),--cpus $(HOST_TUNING_CPUS)) $(if $(strip $(HOST_TUNING_GOVERNOR)),--governor $(HOST_TUNING_GOVERNOR)) $(if $(filter on,$(HOST_TUNING_DISABLE_BOOST)),--disable-boost,) -- ,) \
	$(DOCKER) run --rm \
                --cap-add=NET_ADMIN \
                --cap-add=NET_RAW \
                --cap-add=SYS_NICE \
                --ulimit rtprio=99 \
                --ulimit nice=-20 \
                -e MODE=$(MODE) \
                -e KEM=$(KEM) \
                -e SIG=$(SIG) \
                -e COUNT=$(COUNT) \
                -e QUIC_MODE=$(QUIC_MODE) \
                -e LOSS_PROFILE=$(LOSS_PROFILE) \
                -e NETEM_INTERFACE=$(NETEM_INTERFACE) \
                -e ACK_PAD=$(ACK_PAD) \
                -e DEBUG_LOG=$(DEBUG_LOG) \
                -e MEASURE_ONLY=$(MEASURE_ONLY) \
                -e PRINT_MODE=$(PRINT_MODE) \
                -e RESULTS_DIR=/app/results \
                -e HOST_UID=$(HOST_UID) \
                -e HOST_GID=$(HOST_GID) \
                -e PIN_SERVER_CPU=$(if $(strip $(PIN_SERVER_CPU)),$(PIN_SERVER_CPU),$${PIN_SERVER_CPU:-}) \
                -e PIN_CLIENT_CPU=$(if $(strip $(PIN_CLIENT_CPU)),$(PIN_CLIENT_CPU),$${PIN_CLIENT_CPU:-}) \
                $(if $(strip $(HOST_TUNING_CPUS)),--cpuset-cpus=$(HOST_TUNING_CPUS)) \
                -e HOST_TUNING_STATE_FILE=/run/host_tuning/state.json \
                -e HOST_TUNING_STATE_JSON \
                -v $(HOST_TUNING_STATE_DIR_ABS):/run/host_tuning:rw \
                -v $(RESULTS_DIR):/app/results \
                $(IMAGE_NAME)


packetCount:
	@if ! $(DOCKER) image inspect $(IMAGE_NAME) >/dev/null 2>&1; then \
		echo "Docker image '$(IMAGE_NAME)' not found. Run 'make build' before 'make packetCount'."; \
		exit 1; \
	fi
	mkdir -p $(RESULTS_DIR)
	$(if $(filter on,$(HOST_TUNING)),PIN_SERVER_CPU=$(PIN_SERVER_CPU) PIN_CLIENT_CPU=$(PIN_CLIENT_CPU) HOST_TUNING_STATE_DIR=$(HOST_TUNING_STATE_DIR_ABS) $(HOST_TUNING_SCRIPT) $(if $(strip $(HOST_TUNING_CPUS)),--cpus $(HOST_TUNING_CPUS)) $(if $(strip $(HOST_TUNING_GOVERNOR)),--governor $(HOST_TUNING_GOVERNOR)) $(if $(filter on,$(HOST_TUNING_DISABLE_BOOST)),--disable-boost,) -- ,) \
	$(DOCKER) run --rm \
                --cap-add=NET_ADMIN \
                --cap-add=NET_RAW \
                --cap-add=SYS_NICE \
                --ulimit rtprio=99 \
                --ulimit nice=-20 \
                -e MODE=$(MODE) \
                -e KEM=$(KEM) \
                -e SIG=$(SIG) \
                -e QUIC_MODE=$(QUIC_MODE) \
                -e LOSS_PROFILE=$(LOSS_PROFILE) \
                -e NETEM_INTERFACE=$(NETEM_INTERFACE) \
                -e ACK_PAD=$(ACK_PAD) \
                -e DEBUG_LOG=$(DEBUG_LOG) \
                -e MEASURE_ONLY=$(MEASURE_ONLY) \
                -e PRINT_MODE=packet \
                -e RESULTS_DIR=/app/results \
                -e HOST_UID=$(HOST_UID) \
                -e HOST_GID=$(HOST_GID) \
                -e BENCH_KIND=packetcount \
                -e PIN_SERVER_CPU=$(if $(strip $(PIN_SERVER_CPU)),$(PIN_SERVER_CPU),$${PIN_SERVER_CPU:-}) \
                -e PIN_CLIENT_CPU=$(if $(strip $(PIN_CLIENT_CPU)),$(PIN_CLIENT_CPU),$${PIN_CLIENT_CPU:-}) \
                $(if $(strip $(HOST_TUNING_CPUS)),--cpuset-cpus=$(HOST_TUNING_CPUS)) \
                -e HOST_TUNING_STATE_FILE=/run/host_tuning/state.json \
                -e HOST_TUNING_STATE_JSON \
                -v $(HOST_TUNING_STATE_DIR_ABS):/run/host_tuning:rw \
                -v $(RESULTS_DIR):/app/results \
                $(IMAGE_NAME)

diagram:
	@if [ -z "$(KEM)" ] || [ -z "$(SIG)" ]; then \
		echo "diagram target requires KEM and SIG (use 'make diagram MODE=one KEM=... SIG=...')."; \
		exit 1; \
	fi
	@if ! $(DOCKER) image inspect $(IMAGE_NAME) >/dev/null 2>&1; then \
		echo "Docker image '$(IMAGE_NAME)' not found. Run 'make build' before 'make diagram'."; \
		exit 1; \
	fi
	mkdir -p $(RESULTS_DIR)
	@set -euo pipefail; \
	combo=$$(echo "$(KEM)__$(SIG)" | tr '[:upper:]' '[:lower:]'); \
	find_latest() { \
		python3 scripts/generate_packet_diagram.py \
			--results-root "$(RESULTS_DIR)" \
			--kem "$(KEM)" \
			--sig "$(SIG)" \
			--mode "$(MODE)" \
			--quic-mode "$(QUIC_MODE)" \
			--print-latest-run \
			--relative; \
	}; \
	run_rel=$$(find_latest 2>/dev/null || true); \
	if [ -z "$$run_rel" ]; then \
		echo "No packet-mode run found for $(KEM)/$(SIG); executing benchmark..."; \
		$(if $(filter on,$(HOST_TUNING)),PIN_SERVER_CPU=$(PIN_SERVER_CPU) PIN_CLIENT_CPU=$(PIN_CLIENT_CPU) HOST_TUNING_STATE_DIR=$(HOST_TUNING_STATE_DIR_ABS) $(HOST_TUNING_SCRIPT) $(if $(strip $(HOST_TUNING_CPUS)),--cpus $(HOST_TUNING_CPUS)) $(if $(strip $(HOST_TUNING_GOVERNOR)),--governor $(HOST_TUNING_GOVERNOR)) $(if $(filter on,$(HOST_TUNING_DISABLE_BOOST)),--disable-boost,) -- ,) \
		$(DOCKER) run --rm \
                --cap-add=NET_ADMIN \
                --cap-add=NET_RAW \
                --cap-add=SYS_NICE \
                --ulimit rtprio=99 \
                --ulimit nice=-20 \
                -e MODE=$(MODE) \
                -e KEM=$(KEM) \
                -e SIG=$(SIG) \
                -e COUNT=1 \
                -e QUIC_MODE=$(QUIC_MODE) \
                -e LOSS_PROFILE=$(LOSS_PROFILE) \
                -e NETEM_INTERFACE=$(NETEM_INTERFACE) \
                -e ACK_PAD=$(ACK_PAD) \
                -e DEBUG_LOG=$(DEBUG_LOG) \
                -e MEASURE_ONLY=$(MEASURE_ONLY) \
                -e PRINT_MODE=packet \
                -e RESULTS_DIR=/app/results \
                -e HOST_UID=$(HOST_UID) \
                -e HOST_GID=$(HOST_GID) \
                -e PIN_SERVER_CPU=$(if $(strip $(PIN_SERVER_CPU)),$(PIN_SERVER_CPU),$${PIN_SERVER_CPU:-}) \
                -e PIN_CLIENT_CPU=$(if $(strip $(PIN_CLIENT_CPU)),$(PIN_CLIENT_CPU),$${PIN_CLIENT_CPU:-}) \
                $(if $(strip $(HOST_TUNING_CPUS)),--cpuset-cpus=$(HOST_TUNING_CPUS)) \
                -e HOST_TUNING_STATE_FILE=/run/host_tuning/state.json \
                -e HOST_TUNING_STATE_JSON \
                -v $(HOST_TUNING_STATE_DIR_ABS):/run/host_tuning:rw \
                -v $(RESULTS_DIR):/app/results \
                $(IMAGE_NAME); \
		run_rel=$$(find_latest); \
		if [ -z "$$run_rel" ]; then \
			echo "Benchmark completed but no logs were found for $(KEM)/$(SIG)."; \
			exit 1; \
		fi; \
	else \
		echo "Reusing latest packet-mode run: $$run_rel"; \
	fi; \
	echo "Generating packet diagram from $$run_rel"; \
	$(DOCKER) run --rm \
		-v $(RESULTS_DIR):/data \
		--entrypoint sh \
		$(IMAGE_NAME) \
		-c "mkdir -p /data/diagram && chown -R $(HOST_UID):$(HOST_GID) /data/diagram" >/dev/null 2>&1 || true; \
	$(DOCKER) run --rm \
		-v $(RESULTS_DIR):/app/results \
		-v $(CURDIR)/scripts:/ext_scripts:ro \
		-u $(HOST_UID):$(HOST_GID) \
		--entrypoint python3 \
		$(IMAGE_NAME) \
		/ext_scripts/generate_packet_diagram.py \
			--results-root /app/results \
			--run-dir "$$run_rel" \
			--kem $(KEM) \
			--sig $(SIG) \
			--mode $(MODE) \
			--quic-mode $(QUIC_MODE) \
			--output-root /app/results/diagram; \
	$(DOCKER) run --rm \
		-u $(HOST_UID):$(HOST_GID) \
		-v $(RESULTS_DIR):/data \
		$(MERMAID_CLI_IMAGE) \
		-i "/data/diagram/$$combo/$$combo.mmd" \
		-o "/data/diagram/$$combo/$$combo.pdf" \
		--pdfFit


clean:
	rm -rf $(RESULTS_DIR)

host-status:
	@HOST_TUNING_STATE_DIR=$(HOST_TUNING_STATE_DIR_ABS) $(HOST_TUNING_STATUS_SCRIPT)
