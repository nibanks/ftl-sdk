/**
 * activate.c - Activates an FTL stream
 *
 * Copyright (c) 2015 Michael Casadevall
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 **/

#define __FTL_INTERNAL
#include "ftl.h"
#include "ftl_private.h"
#include "hmac/hmac.h"
#include <stdarg.h>

QUIC_CONNECTION_CALLBACK quic_connection_callback;
QUIC_STREAM_CALLBACK quic_auth_stream_callback;
QUIC_STREAM_CALLBACK quic_config_stream_callback;

static ftl_response_code_t _ftl_send_command(ftl_stream_configuration_private_t* ftl, HQUIC stream, const char* cmd_fmt, ...);

ftl_status_t _ingest_connect(ftl_stream_configuration_private_t* ftl) {
  ftl_status_t retval = FTL_SUCCESS;

  if (ftl_get_state(ftl, FTL_CONNECTED)) {
    return FTL_ALREADY_CONNECTED;
  }

  if ((retval = _set_ingest_hostname(ftl)) != FTL_SUCCESS) {
    return retval;
  }

  do {
    QUIC_STATUS status;
    QUIC_BUFFER alpn = { sizeof("flt")-1, (uint8_t*)"flt" };

    status = msquic->SessionOpen(quic_registration, &alpn, 1, 0, &ftl->ingest_session);
    if (QUIC_FAILED(status)) {
      FTL_LOG(ftl, FTL_LOG_ERROR, "failed to open quic session.  error: 0x%x", status);
      retval = FTL_MALLOC_FAILURE; // TODO - Map errors?
      break;
    }

    status = msquic->ConnectionOpen(ftl->ingest_session, quic_connection_callback, ftl, &ftl->ingest_connection);
    if (QUIC_FAILED(status)) {
      FTL_LOG(ftl, FTL_LOG_ERROR, "failed to open quic connection.  error: 0x%x", status);
      retval = FTL_CONNECT_ERROR; // TODO - Map errors?
      break;
    }

    uint16_t peer_bidi_stream_count = 1;
    status = msquic->SetParam(
      ftl->ingest_connection,
      QUIC_PARAM_LEVEL_CONNECTION,
      QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT,
      sizeof(peer_bidi_stream_count),
      &peer_bidi_stream_count);
    if (QUIC_FAILED(status)) {
      FTL_LOG(ftl, FTL_LOG_ERROR, "failed to set param PEER_BIDI_STREAM_COUNT.  error: 0x%x", status);
      retval = FTL_CONNECT_ERROR; // TODO - Map errors?
      break;
    }

    status = msquic->ConnectionStart(ftl->ingest_connection, AF_UNSPEC, ftl->ingest_hostname, INGEST_PORT);
    if (QUIC_FAILED(status)) {
      FTL_LOG(ftl, FTL_LOG_ERROR, "failed to start quic connection.  error: 0x%x", status);
      retval = FTL_CONNECT_ERROR; // TODO - Map errors?
      break;
    }
  } while (0);

  if (ftl->ingest_connection) {
    msquic->ConnectionClose(ftl->ingest_connection);
    ftl->ingest_connection = 0;
  }

  if (ftl->ingest_session) {
    msquic->SessionClose(ftl->ingest_session);
    ftl->ingest_session = 0;
  }

  return retval;
}

void _ingest_authenticate(ftl_stream_configuration_private_t *ftl) {
    ftl_response_code_t response_code;

  do {

    hmacsha512(ftl->key, ftl->challengeBuffer, ftl->challengeBufferLength, ftl->hmacBuffer);
    if ((response_code = _ftl_send_command(ftl, ftl->ingest_auth_stream, "CONNECT %d $%s", ftl->channel_id, ftl->hmacBuffer)) != FTL_INGEST_RESP_OK) {
      break;
    }

    /* Tell the server that's the end of our authentication */
    if (QUIC_FAILED(msquic->StreamShutdown(ftl->ingest_auth_stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0))) {
        break;
    }

    /* Open a new stream to send configuration data */
    if (QUIC_FAILED(msquic->StreamOpen(ftl->ingest_connection, 0, quic_config_stream_callback, ftl, &ftl->ingest_config_stream)) ||
        QUIC_FAILED(msquic->StreamStart(ftl->ingest_config_stream, QUIC_STREAM_START_FLAG_NONE))) {
        break;
    }

    // TODO - The following should be sent all at once. Ideally as a binary blob.

    if ((response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "ProtocolVersion: %d.%d", FTL_VERSION_MAJOR, FTL_VERSION_MINOR)) != FTL_INGEST_RESP_OK ||
        (response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "VendorName: %s", ftl->vendor_name)) != FTL_INGEST_RESP_OK ||
        (response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "VendorVersion: %s", ftl->vendor_version)) != FTL_INGEST_RESP_OK) {
      break;
    }

    ftl_video_component_t *video = &ftl->video;
    /* We're sending video */
    if ((response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "Video: true")) != FTL_INGEST_RESP_OK ||
        (response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "VideoCodec: %s", ftl_video_codec_to_string(video->codec))) != FTL_INGEST_RESP_OK ||
        (response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "VideoHeight: %d", video->height)) != FTL_INGEST_RESP_OK ||
        (response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "VideoWidth: %d", video->width)) != FTL_INGEST_RESP_OK ||
        (response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "VideoPayloadType: %d", video->media_component.payload_type)) != FTL_INGEST_RESP_OK ||
        (response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "VideoIngestSSRC: %d", video->media_component.ssrc)) != FTL_INGEST_RESP_OK) {
        break;
    }


    ftl_audio_component_t *audio = &ftl->audio;
    if ((response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "Audio: true")) != FTL_INGEST_RESP_OK ||
        (response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "AudioCodec: %s", ftl_audio_codec_to_string(audio->codec))) != FTL_INGEST_RESP_OK ||
        (response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "AudioPayloadType: %d", audio->media_component.payload_type)) != FTL_INGEST_RESP_OK ||
        (response_code = _ftl_send_command(ftl, ftl->ingest_config_stream, "AudioIngestSSRC: %d", audio->media_component.ssrc)) != FTL_INGEST_RESP_OK) {
        break;
    }

    /* Tell the server that's the end of our config */
    if (QUIC_FAILED(msquic->StreamShutdown(ftl->ingest_config_stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0))) {
        break;
    }

    return;
  } while (0);

  _ingest_disconnect(ftl);
}

void _ingest_handshake_complete(ftl_stream_configuration_private_t* ftl) {

    ftl_set_state(ftl, FTL_CONNECTED);

    FTL_LOG(ftl, FTL_LOG_INFO, "Successfully connected to ingest.\n");

    media_init(ftl);
}

ftl_status_t _ingest_disconnect(ftl_stream_configuration_private_t *ftl) {

    if (ftl->ingest_connection) {
        if (ftl_get_state(ftl, FTL_CONNECTED)) {
            ftl_clear_state(ftl, FTL_CONNECTED);
            FTL_LOG(ftl, FTL_LOG_INFO, "light-saber disconnect\n");
        }
        msquic->ConnectionShutdown(ftl->ingest_connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0); // TODO - Send a better error code
    }

    if (ftl_get_state(ftl, FTL_BITRATE_THRD))
    {
        ftl_clear_state(ftl, FTL_BITRATE_THRD);
        os_semaphore_post(&ftl->bitrate_thread_shutdown);
        os_wait_thread(ftl->bitrate_monitor_thread);
        os_destroy_thread(ftl->bitrate_monitor_thread);
        os_semaphore_delete(&ftl->bitrate_thread_shutdown);
    }

    if (ftl->ingest_config_stream) {
        msquic->StreamClose(ftl->ingest_config_stream);
        ftl->ingest_config_stream = 0;
    }

    if (ftl->ingest_auth_stream) {
        msquic->StreamClose(ftl->ingest_auth_stream);
        ftl->ingest_auth_stream = 0;
    }

    if (ftl->ingest_connection) {
        // TODO - Wait for shutdown complete
        msquic->ConnectionClose(ftl->ingest_connection);
        ftl->ingest_connection = 0;
    }

    if (ftl->ingest_session) {
        msquic->SessionClose(ftl->ingest_session);
        ftl->ingest_session = 0;
    }

    return FTL_SUCCESS;
}

static ftl_response_code_t _ftl_send_command(ftl_stream_configuration_private_t* ftl, HQUIC stream, const char* cmd_fmt, ...) {
  int resp_code = FTL_INGEST_RESP_OK;
  va_list valist;
  char *buf = NULL;
  int len;
  int buflen = MAX_INGEST_COMMAND_LEN * sizeof(char);
  char *format = NULL;
  QUIC_BUFFER* quic_buf;

  do {
    if ((quic_buf = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER) + buflen)) == NULL) {
      resp_code = FTL_INGEST_RESP_INTERNAL_MEMORY_ERROR;
      break;
    }

    if ((format = (char*)malloc(strlen(cmd_fmt) + 5)) == NULL) {
      resp_code = FTL_INGEST_RESP_INTERNAL_MEMORY_ERROR;
      break;
    }

    buf = (char*)(quic_buf + 1);

    sprintf_s(format, strlen(cmd_fmt) + 5, "%s\r\n\r\n", cmd_fmt);

    va_start(valist, cmd_fmt);

    memset(buf, 0, buflen);

    len = vsnprintf(buf, buflen, format, valist);

    va_end(valist);

    if (len < 0 || len >= buflen) {
      resp_code = FTL_INGEST_RESP_INTERNAL_COMMAND_ERROR;
      break;
    }

    quic_buf->Buffer = buf;
    quic_buf->Length = (uint32_t)len;

    if (QUIC_SUCCEEDED(msquic->StreamSend(stream, quic_buf, 1, 0, quic_buf))) {
      quic_buf = NULL;
    }
  } while (0);

  if (quic_buf != NULL){
    free(quic_buf);
  }

  if (format != NULL){
    free(format);
  }

  return resp_code;
}

ftl_status_t _log_response(ftl_stream_configuration_private_t *ftl, int response_code){

  switch (response_code) {
    case FTL_INGEST_RESP_OK:
      FTL_LOG(ftl, FTL_LOG_DEBUG, "ingest accepted our paramteres");
    return FTL_SUCCESS;
    case FTL_INGEST_NO_RESPONSE:
      FTL_LOG(ftl, FTL_LOG_ERROR, "ingest did not respond to request");
      return FTL_INGEST_NO_RESPONSE;
    case FTL_INGEST_RESP_PING:
      return FTL_SUCCESS;
    case FTL_INGEST_RESP_BAD_REQUEST:
      FTL_LOG(ftl, FTL_LOG_ERROR, "ingest responded bad request");
      return FTL_BAD_REQUEST;
    case FTL_INGEST_RESP_UNAUTHORIZED:
      FTL_LOG(ftl, FTL_LOG_ERROR, "channel is not authorized for FTL");
      return FTL_UNAUTHORIZED;
    case FTL_INGEST_RESP_OLD_VERSION:
      FTL_LOG(ftl, FTL_LOG_ERROR, "This version of the FTLSDK is depricated");
      return FTL_OLD_VERSION;
    case FTL_INGEST_RESP_AUDIO_SSRC_COLLISION:
      FTL_LOG(ftl, FTL_LOG_ERROR, "audio SSRC collision from this IP address. Please change your audio SSRC to an unused value");
      return FTL_AUDIO_SSRC_COLLISION;
    case FTL_INGEST_RESP_VIDEO_SSRC_COLLISION:
      FTL_LOG(ftl, FTL_LOG_ERROR, "video SSRC collision from this IP address. Please change your audio SSRC to an unused value");
      return FTL_VIDEO_SSRC_COLLISION;
    case FTL_INGEST_RESP_INVALID_STREAM_KEY:
      FTL_LOG(ftl, FTL_LOG_ERROR, "The stream key or channel id is incorrect");
      return FTL_BAD_OR_INVALID_STREAM_KEY;
    case FTL_INGEST_RESP_CHANNEL_IN_USE:
      FTL_LOG(ftl, FTL_LOG_ERROR, "the channel id is already actively streaming");
      return FTL_CHANNEL_IN_USE;
    case FTL_INGEST_RESP_REGION_UNSUPPORTED:
      FTL_LOG(ftl, FTL_LOG_ERROR, "the region is not authorized to stream");
      return FTL_REGION_UNSUPPORTED;
    case FTL_INGEST_RESP_NO_MEDIA_TIMEOUT:
      FTL_LOG(ftl, FTL_LOG_ERROR, "The server did not receive media (audio or video) for an extended period of time");
      return FTL_NO_MEDIA_TIMEOUT;
    case FTL_INGEST_RESP_INTERNAL_SERVER_ERROR:
      FTL_LOG(ftl, FTL_LOG_ERROR, "parameters accepted, but ingest couldn't start FTL. Please contact support!");
      return FTL_INTERNAL_ERROR;
    case FTL_INGEST_RESP_GAME_BLOCKED:
      FTL_LOG(ftl, FTL_LOG_ERROR, "The current game set by this profile can't be streamed.");
      return FTL_GAME_BLOCKED;
    case FTL_INGEST_RESP_INTERNAL_MEMORY_ERROR:
      FTL_LOG(ftl, FTL_LOG_ERROR, "Server memory error");
      return FTL_INTERNAL_ERROR;
    case FTL_INGEST_RESP_INTERNAL_COMMAND_ERROR:
      FTL_LOG(ftl, FTL_LOG_ERROR, "Server command error");
      return FTL_INTERNAL_ERROR;
    case FTL_INGEST_RESP_INTERNAL_SOCKET_CLOSED:
      FTL_LOG(ftl, FTL_LOG_ERROR, "Ingest socket closed.");
      return FTL_INGEST_SOCKET_CLOSED;
    case FTL_INGEST_RESP_INTERNAL_SOCKET_TIMEOUT:
      FTL_LOG(ftl, FTL_LOG_ERROR, "Ingest socket timeout.");
      return FTL_INGEST_SOCKET_TIMEOUT;
    case FTL_INGEST_RESP_SERVER_TERMINATE:
      FTL_LOG(ftl, FTL_LOG_ERROR, "The server has terminated the stream.");
      return FTL_INGEST_SERVER_TERMINATE;
    case FTL_INGEST_RESP_UNKNOWN:
        FTL_LOG(ftl, FTL_LOG_ERROR, "Ingest unknown response.");
        return FTL_INTERNAL_ERROR;
  }    

  return FTL_UNKNOWN_ERROR_CODE;
}

QUIC_STATUS
QUIC_API
quic_connection_callback(
    _In_ HQUIC connection,
    _In_opt_ void* context,
    _Inout_ QUIC_CONNECTION_EVENT* event
    )
{
    ftl_stream_configuration_private_t *ftl = (ftl_stream_configuration_private_t *)context;
    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      _log_response(ftl, (int)event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
      if (event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL)
        return QUIC_STATUS_NOT_SUPPORTED;
      if (ftl->ingest_auth_stream == 0) {
        ftl->challengeBufferLength = 0;
        ftl->ingest_auth_stream = event->PEER_STREAM_STARTED.Stream;
        msquic->SetCallbackHandler(event->PEER_STREAM_STARTED.Stream, quic_auth_stream_callback, ftl);
      } else {
        return QUIC_STATUS_NOT_SUPPORTED;
      }
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
      media_datagram_send_state_changed(
        ftl,
        event->DATAGRAM_SEND_STATE_CHANGED.State,
        &event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
      break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QUIC_API
quic_auth_stream_callback(
    _In_ HQUIC stream,
    _In_opt_ void* context,
    _Inout_ QUIC_STREAM_EVENT* event
    )
{
    ftl_stream_configuration_private_t *ftl = (ftl_stream_configuration_private_t *)context;
    switch (event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
      for (uint32_t i = 0; i < event->RECEIVE.BufferCount; ++i) {
        if (event->RECEIVE.Buffers[i].Length + ftl->challengeBufferLength > sizeof(ftl->challengeBuffer)) {
          msquic->ConnectionShutdown(ftl->ingest_connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 1); // TODO - Set an error code.
          break;
        }
        memcpy(
          ftl->challengeBuffer + ftl->challengeBufferLength,
          event->RECEIVE.Buffers[i].Buffer,
          event->RECEIVE.Buffers[i].Length);
      }
      break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      free(event->SEND_COMPLETE.ClientContext); // Our buffer we allocated for sending.
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      // We now have all the challenge buffer. Send the response.
      _ingest_authenticate(ftl);
      break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QUIC_API
quic_config_stream_callback(
    _In_ HQUIC stream,
    _In_opt_ void* context,
    _Inout_ QUIC_STREAM_EVENT* event
    )
{
    ftl_stream_configuration_private_t *ftl = (ftl_stream_configuration_private_t *)context;
    switch (event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      free(event->SEND_COMPLETE.ClientContext); // Our buffer we allocated for sending.
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      // Yay. Server accepted our config.
      _ingest_handshake_complete(ftl);
      break;
    }
    return QUIC_STATUS_SUCCESS;
}
