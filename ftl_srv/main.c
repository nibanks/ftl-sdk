/**
 * main.c - QUIC server for the FTL SDK
 *
 * Copyright (c) Microsoft Corporation. All rights reserved.
 *
 **/

#if _WIN32
#define WIN32_LEAN_AND_MEAN 1
#endif

#include <msquic.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <conio.h>

#define INGEST_PORT 8084

const QUIC_API_TABLE* msquic;
HQUIC quic_registration;
QUIC_SEC_CONFIG* quic_sec_config;

QUIC_LISTENER_CALLBACK quic_listener_callback;
QUIC_CONNECTION_CALLBACK quic_connection_callback;
QUIC_STREAM_CALLBACK quic_auth_stream_callback;
QUIC_STREAM_CALLBACK quic_config_stream_callback;

typedef struct _FTL_CONNECTION {
    HQUIC connection;
    HQUIC auth_stream;
    HQUIC config_stream;

    uint8_t authenticated : 1;
    uint8_t configured : 1;

    QUIC_BUFFER challenge_send_buf;
    uint8_t challenge[256]; // TODO - what size?

    uint64_t recv_datagrams;
    uint64_t recv_bytes;
} FTL_CONNECTION;

FTL_CONNECTION* ftl_conn_create(HQUIC connection);

void usage() {
    printf("Usage:\n\tftl_srv -t <cert_thumbprint>\n\tftl_srv -f <cert_file> -k <key_file>\n");
    exit(0);
}

uint8_t DecodeHexChar(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return 0;
}

uint32_t
DecodeHexBuffer(
    _In_z_ const char* HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return)
        uint8_t* OutBuffer
)
{
    uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
    if (HexBufferLen > OutBufferLen) {
        return 0;
    }

    for (uint32_t i = 0; i < HexBufferLen; i++) {
        OutBuffer[i] =
            (DecodeHexChar(HexBuffer[i * 2]) << 4) |
            DecodeHexChar(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}

void
QUIC_API
quic_create_sec_config_complete(
    _In_opt_ void* context,
    _In_ QUIC_STATUS status,
    _In_opt_ QUIC_SEC_CONFIG* security_config
)
{
    if (QUIC_FAILED(status)) {
        fprintf(stderr, "create sec config completion failed: 0x%x\n", status);
    }
    else {
        quic_sec_config = security_config;
    }
}

QUIC_STATUS
quic_create_sec_config_from_thumbprint(
    _In_z_ char* cert_thumprint
    )
{
    QUIC_CERTIFICATE_HASH hash;
    if (sizeof(hash.ShaHash) !=
        DecodeHexBuffer(
            cert_thumprint,
            sizeof(hash.ShaHash),
            hash.ShaHash)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    return
        msquic->SecConfigCreate(
            quic_registration,
            QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH,
            &hash,
            NULL,
            NULL,
            quic_create_sec_config_complete);
}

QUIC_STATUS
quic_create_sec_config_from_file(
    _In_z_ char* cert_file,
    _In_z_ char* key_file
    )
{
    QUIC_CERTIFICATE_FILE CertFile;
    CertFile.PrivateKeyFile = key_file;
    CertFile.CertificateFile = cert_file;
    return
        msquic->SecConfigCreate(
            quic_registration,
            QUIC_SEC_CONFIG_FLAG_CERTIFICATE_FILE,
            &CertFile,
            NULL,
            NULL,
            quic_create_sec_config_complete);
}

QUIC_STATUS
QUIC_API
quic_listener_callback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        printf("New connection.\n");
        if (quic_sec_config == NULL) {
            return QUIC_STATUS_INVALID_STATE;
        } else if (!ftl_conn_create(Event->NEW_CONNECTION.Connection)) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        Event->NEW_CONNECTION.SecurityConfig = quic_sec_config;
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

FTL_CONNECTION* ftl_conn_create(HQUIC connection)
{
    FTL_CONNECTION* ftl_conn;
    do {
        ftl_conn = (FTL_CONNECTION*)malloc(sizeof(FTL_CONNECTION));
        if (ftl_conn == NULL) break;

        memset(ftl_conn, 0, sizeof(FTL_CONNECTION));
        ftl_conn->connection = connection;
        // TODO - randomize ftl_conn->challenge;
        msquic->SetCallbackHandler(connection, quic_connection_callback, ftl_conn);

        ftl_conn->challenge_send_buf.Length = sizeof(ftl_conn->challenge);
        ftl_conn->challenge_send_buf.Buffer = ftl_conn->challenge;

        QUIC_STATUS status;

        BOOLEAN datagram_recv_enabled = 1;
        status = msquic->SetParam(
            ftl_conn->connection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
            sizeof(datagram_recv_enabled),
            &datagram_recv_enabled);
        if (QUIC_FAILED(status)) {
            break;
        }

        // Open a new stream back to the client to send the challenge buffer
        if (QUIC_FAILED(status = msquic->StreamOpen(ftl_conn->connection, 0, quic_auth_stream_callback, ftl_conn, &ftl_conn->auth_stream)) ||
            QUIC_FAILED(status = msquic->StreamStart(ftl_conn->auth_stream, 0)) ||
            QUIC_FAILED(status = msquic->StreamSend(ftl_conn->auth_stream, &ftl_conn->challenge_send_buf, 1, QUIC_SEND_FLAG_FIN, NULL))) {
            break;
        }

        return ftl_conn;
    } while (0);

    if (ftl_conn) {
        if (ftl_conn->auth_stream) {
            msquic->StreamClose(ftl_conn->auth_stream);
        }
        free(ftl_conn);
    }

    return NULL;
}

void ftl_conn_destroy(FTL_CONNECTION* ftl_conn)
{
    if (ftl_conn->auth_stream) {
        msquic->StreamClose(ftl_conn->auth_stream);
    }

    if (ftl_conn->config_stream) {
        msquic->StreamClose(ftl_conn->config_stream);
    }

    msquic->ConnectionClose(ftl_conn->connection);
    free(ftl_conn);
}

void ftl_conn_authenticate(FTL_CONNECTION* ftl_conn)
{
    // TODO - Validate. If failure, shutdown connection.
    ftl_conn->authenticated = 1;
    printf("Authenticated.\n");
}

void ftl_conn_configure(FTL_CONNECTION* ftl_conn)
{
    // TODO - Validate. If failure, shutdown connection.
    ftl_conn->configured = 1;
    printf("Configured.\n");

    // Tell the client we accept their config.
    msquic->StreamShutdown(ftl_conn->config_stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
}

void ftl_conn_recv_datagram(FTL_CONNECTION* ftl_conn, const QUIC_BUFFER* datagram)
{
    //printf("Datagram recv, %u bytes.\n", datagram->Length);
    ftl_conn->recv_datagrams++;
    ftl_conn->recv_bytes += datagram->Length;
    // TODO - Process received datagram
}

QUIC_STATUS
QUIC_API
quic_connection_callback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    FTL_CONNECTION* ftl_conn = (FTL_CONNECTION*)Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("Connection terminated (%llu datagrams, %llu bytes).\n", ftl_conn->recv_datagrams, ftl_conn->recv_bytes);
        ftl_conn_destroy(ftl_conn);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        if (Event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        } else if (!ftl_conn->config_stream) {
            ftl_conn->config_stream = Event->PEER_STREAM_STARTED.Stream;
            msquic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, quic_config_stream_callback, ftl_conn);
        } else {
            return QUIC_STATUS_INVALID_STATE;
        }
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        ftl_conn_recv_datagram(ftl_conn, Event->DATAGRAM_RECEIVED.Buffer);
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QUIC_API
quic_auth_stream_callback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    FTL_CONNECTION* ftl_conn = (FTL_CONNECTION*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        // TODO - Copy locally
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        ftl_conn_authenticate(ftl_conn);
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QUIC_API
quic_config_stream_callback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    FTL_CONNECTION* ftl_conn = (FTL_CONNECTION*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        // TODO - Copy locally
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        ftl_conn_configure(ftl_conn);
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

int main(int argc, char **argv)
{
    QUIC_STATUS status;
    char *cert_thumbprint = NULL;
    char* cert_file = NULL;
    char* key_file = NULL;
    HQUIC session = NULL;
    HQUIC listener = NULL;
    QUIC_BUFFER alpn = { sizeof("flt")-1, (uint8_t*)"flt" };

    argc--; argv++;
    while (argc) {
        if (!strcmp(*argv, "-t")) {
            if (argc > 1) {
                argc--; argv++;
                cert_thumbprint = *argv;
            } else {
                fprintf(stderr, "'-t' option missing second parameter\n");
            }
        } else if (!strcmp(*argv, "-c")) {
            if (argc > 1) {
                argc--; argv++;
                cert_file = *argv;
            } else {
                fprintf(stderr, "'-c' option missing second parameter\n");
            }
        } else if (!strcmp(*argv, "-k")) {
            if (argc > 1) {
                argc--; argv++;
                key_file = *argv;
            } else {
                fprintf(stderr, "'-k' option missing second parameter\n");
            }
        } else {
            fprintf(stderr, "Unknown '%s' option\n", *argv);
        }

        argc--; argv++;
    }

    if (cert_thumbprint == NULL || (cert_file == NULL && key_file == NULL)) {
        usage();
    }

    if (QUIC_FAILED(status = MsQuicOpen(&msquic))) {
        fprintf(stderr, "MsQuicOpen failed: 0x%x\n", status);
        goto cleanup;
    }

    const QUIC_REGISTRATION_CONFIG reg_config = { "flt-srv", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    if (QUIC_FAILED(msquic->RegistrationOpen(&reg_config, &quic_registration))) {
        fprintf(stderr, "create registration failed: 0x%x\n", status);
        goto cleanup;
    }

    if (cert_thumbprint) {
        if (QUIC_FAILED(status = quic_create_sec_config_from_thumbprint(cert_thumbprint))) {
            fprintf(stderr, "create sec config failed: 0x%x\n", status);
            goto cleanup;
        }
    } else {
        if (QUIC_FAILED(status = quic_create_sec_config_from_file(cert_file, key_file))) {
            fprintf(stderr, "create sec config failed: 0x%x\n", status);
            goto cleanup;
        }
    }

    if (QUIC_FAILED(status = msquic->SessionOpen(quic_registration, &alpn, 1, NULL, &session))) {
        fprintf(stderr, "session open failed: 0x%x\n", status);
        goto cleanup;
    }

    uint16_t peer_streams = 1;
    if (QUIC_FAILED(status = msquic->SetParam(session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(peer_streams), &peer_streams))) {
        fprintf(stderr, "session set peer streams failed: 0x%x\n", status);
        goto cleanup;
    }

    if (QUIC_FAILED(status = msquic->ListenerOpen(session, quic_listener_callback, NULL, &listener))) {
        fprintf(stderr, "listener open failed: 0x%x\n", status);
        goto cleanup;
    }

    QUIC_ADDR listen_addr = { 0 };
    QuicAddrSetPort(&listen_addr, INGEST_PORT);
    if (QUIC_FAILED(status = msquic->ListenerStart(listener, &listen_addr))) {
        fprintf(stderr, "listener start failed: 0x%x\n", status);
        goto cleanup;
    }

    printf("Press Enter to exit.\n\n");
    getchar();

cleanup:

    if (listener) {
        msquic->ListenerClose(listener);
    }

    if (session) {
        msquic->SessionShutdown(session, 0, 0); // TODO - Pick an error code
        msquic->SessionClose(session);
    }

    if (quic_sec_config) {
        msquic->SecConfigDelete(quic_sec_config);
    }

    if (quic_registration) {
        msquic->RegistrationClose(quic_registration);
    }

    if (msquic) {
        MsQuicClose(msquic);
    }

    return (int)status;
}
