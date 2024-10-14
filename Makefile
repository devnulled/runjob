
.DEFAULT_GOAL := all

BUILD_BASE_PATH?=$(shell pwd)
BUILD_BIN_PATH:=${BUILD_BASE_PATH}/bin
BUILD_CERTS_PATH:=${BUILD_BASE_PATH}/certs

BUILD_CERTS_CA_NAME?=root-ca
BUILD_CERTS_SERVER_NAME?=server
BUILD_CERTS_SERVER_HOSTNAME?=localhost
BUILD_CERTS_SERVER_IP?=0.0.0.0

BUILD_CERTS_CA_CERT_SUBJ=/CN=${BUILD_CERTS_CA_NAME}
BUILD_CERTS_SERVER_CERT_SUBJ=/CN=${BUILD_CERTS_SERVER_NAME}

BUILD_CERTS_SRV_KEY_FILENAME?=server-key.pem
BUILD_CERTS_SRV_CERT_FILENAME?=server-cert.pem

BUILD_CERTS_CA_DAYS_VALID?=3650
BUILD_CERTS_SERVER_DAYS_VALID?=365
BUILD_CERTS_CLIENT_DAYS_VALID?=90

BUILD_CERTS_CLIENT_NAME?=client
BUILD_CERTS_CLIENT1_NAME?=client-01
BUILD_CERTS_CLIENT2_NAME?=client-02

BUILD_BIN_DEPS := \
	go\
	openssl\
	protoc\
	protoc-gen-go\
	protoc-gen-go-grpc

.PHONY: all deps build certs-clean certs-gen certs-init certs-clean certs-bundle-client certs-bundle-clients certs-gen-ca
.PHONY: certs-gen-server certs-gen-client certs-gen-clients protoc

all: deps build

deps:
	@for p in $(BUILD_BIN_DEPS); do \
		$(call fn_bin_is_installed,$$p) || exit 1; \
	done

build: deps
	go build -o bin/ ./...

protoc: deps
	protoc \
		--go_opt=paths=source_relative \
		--go_out=. \
		--go-grpc_opt=paths=source_relative \
		--go-grpc_out=. \
		internal/proto/jobmanager_service.proto

certs-gen: deps certs-clean certs-init certs-gen-ca certs-gen-server certs-gen-client certs-gen-clients certs-bundle-clients

certs-init:
	mkdir -p ${BUILD_CERTS_PATH} || true

certs-clean:
	rm -rf ${BUILD_CERTS_PATH}/ || true

certs-gen-ca:
	$(call fn_certs_gen_ca,${BUILD_CERTS_PATH},${BUILD_CERTS_CA_NAME},${BUILD_CERTS_CA_DAYS_VALID},${BUILD_CERTS_CA_CERT_SUBJ})

certs-gen-server:
	$(call fn_certs_gen_server,${BUILD_CERTS_PATH},${BUILD_CERTS_SERVER_NAME},${BUILD_CERTS_SERVER_DAYS_VALID},${BUILD_CERTS_SERVER_CERT_SUBJ},${BUILD_CERTS_SERVER_HOSTNAME},${BUILD_CERTS_SERVER_IP})
	$(call fn_certs_verify,${BUILD_CERTS_PATH},${BUILD_CERTS_SERVER_NAME})

certs-gen-client:
	$(call fn_certs_gen_client,${BUILD_CERTS_PATH},${BUILD_CERTS_CLIENT_NAME},${BUILD_CERTS_CLIENT_DAYS_VALID})
	$(call fn_certs_verify,${BUILD_CERTS_PATH},${BUILD_CERTS_CLIENT_NAME})

certs-gen-clients:
	$(call fn_certs_gen_client,${BUILD_CERTS_PATH},${BUILD_CERTS_CLIENT1_NAME},${BUILD_CERTS_CLIENT_DAYS_VALID})
	$(call fn_certs_verify,${BUILD_CERTS_PATH},${BUILD_CERTS_CLIENT1_NAME})
	$(call fn_certs_gen_client,${BUILD_CERTS_PATH},${BUILD_CERTS_CLIENT2_NAME},${BUILD_CERTS_CLIENT_DAYS_VALID})
	$(call fn_certs_verify,${BUILD_CERTS_PATH},${BUILD_CERTS_CLIENT2_NAME})

certs-bundle-client:
	$(call fn_certs_bundle_client,${BUILD_CERTS_PATH})

certs-bundle-clients:
	$(call fn_certs_bundle_clients,${BUILD_CERTS_PATH})




#
# Checks to see if a required binary for the build is installed
#
# arg1: binary name
define fn_bin_is_installed
hash $(1) >/dev/null 2>/dev/null || { echo >&2 "The binary '$(1)' is required but not found. Aborting."; exit 1; }
endef

#
# Generate a ECDSA P-384 CA private key & self-signed cert
#
# arg1: Path to generate the certs in
# arg2: Filename prefix
# arg3: Number of days valid
# arg4: Cert subject
define fn_certs_gen_ca
openssl ecparam -genkey -name secp384r1 -out ${1}/${2}-key.pem
openssl req -x509 -new -key ${1}/${2}-key.pem -sha384 -days ${3} -out ${1}/${2}-cert.pem -subj "${4}"
endef

#
# Generate a signed server cert ECDSA P-384
#
# arg1: Path to generate the certs in
# arg2: Filename prefix
# arg3: Number of days valid
# arg4: Cert subject
# arg5: Server hostname
# arg6: Server IP
define fn_certs_gen_server
openssl ecparam -genkey -name secp384r1 -out ${1}/${2}-key.pem
openssl req -new -key ${1}/${2}-key.pem -out ${1}/${2}-csr.csr -subj "${4}" -config config/openssl.conf
openssl x509 -req -in ${1}/${2}-csr.csr -CA ${1}/${BUILD_CERTS_CA_NAME}-cert.pem -CAkey ${1}/${BUILD_CERTS_CA_NAME}-key.pem -CAcreateserial -out ${1}/${2}-cert.pem -days ${3} -sha384 -extensions v3_ext -extfile config/openssl.conf
endef

#
# Generate a signed client cert
#
# arg1: Path to generate the certs in
# arg2: Filename prefix (and username)
# arg3: Number of days valid
define fn_certs_gen_client
openssl ecparam -genkey -name secp384r1 -out ${1}/${2}-key.pem
openssl req -new -key ${1}/${2}-key.pem -out ${1}/${2}-csr.csr -subj "/CN=${2}"
openssl x509 -req -in ${1}/${2}-csr.csr -CA ${1}/${BUILD_CERTS_CA_NAME}-cert.pem -CAkey ${1}/${BUILD_CERTS_CA_NAME}-key.pem -CAcreateserial -out ${1}/${2}-cert.pem -days ${3} -sha384
endef

#
# Generate a client certificate bundle and validate
#
# arg1: Location of certs
# TODO: Hacky but it works. Fix later
define fn_certs_bundle_client
cat ${1}/client-cert.pem ${1}/${BUILD_CERTS_CA_NAME}-cert.pem > ${1}/ca-client-bundle.pem
openssl verify -CAfile ${1}/${BUILD_CERTS_CA_NAME}-cert.pem ${1}/ca-client-bundle.pem
endef

#
# Generate a client certificate bundle of all clients and validate
#
# arg1: Location of certs
# TODO: Hacky but it works. Fix later
define fn_certs_bundle_clients
cat ${1}/client-cert.pem ${1}/client-01-cert.pem ${1}/client-02-cert.pem ${1}/${BUILD_CERTS_CA_NAME}-cert.pem > ${1}/ca-clients-bundle.pem
openssl verify -CAfile ${1}/${BUILD_CERTS_CA_NAME}-cert.pem ${1}/ca-clients-bundle.pem
endef

#
# Validate a signed certificate
#
# arg1: Path where the certs reside
# arg2: Filename prefix of the cert to verify
define fn_certs_verify
openssl verify -CAfile ${1}/${BUILD_CERTS_CA_NAME}-cert.pem ${1}/${2}-cert.pem
endef

#openssl req -new -key ${1}/${2}-key.pem -out ${1}/${2}-csr.csr -subj "${4}" -addext "subjectAltName=DNS:${5},DNS:*.${5},IP:${6}" -addext "subjectAltName=DNS:localhost"
