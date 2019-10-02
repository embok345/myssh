#ifndef MYSSH_NUMBERS_H
#define MYSSH_NUMBERS_H

#include <inttypes.h>

/* Main SSH message codes, as defined in rfc4250 */
extern const uint8_t SSH_MSG_DISCONNECT;
extern const uint8_t SSH_MSG_IGNORE;
extern const uint8_t SSH_MSG_UNIMPLEMENTED;
extern const uint8_t SSH_MSG_DEBUG;
extern const uint8_t SSH_MSG_SERVICE_REQUEST;
extern const uint8_t SSH_MSG_SERVICE_ACCEPT;
extern const uint8_t SSH_MSG_KEXINIT;
extern const uint8_t SSH_MSG_NEWKEYS;
extern const uint8_t SSH_MSG_KEXDH_INIT;
extern const uint8_t SSH_MSG_KEXDH_REPLY;
extern const uint8_t SSH_MSG_USERAUTH_REQUEST;
extern const uint8_t SSH_MSG_USERAUTH_FAILURE;
extern const uint8_t SSH_MSG_USERAUTH_SUCCESS;
extern const uint8_t SSH_MSG_USERAUTH_BANNER;
extern const uint8_t SSH_MSG_USERAUTH_PK_OK;
extern const uint8_t SSH_MSG_USERAUTH_INFO_REQUEST;
extern const uint8_t SSH_MSG_USERAUTH_INFO_RESPONSE;
extern const uint8_t SSH_MSG_GLOBAL_REQUEST;
extern const uint8_t SSH_MSG_REQUEST_SUCCESS;
extern const uint8_t SSH_MSG_REQUEST_FAILURE;
extern const uint8_t SSH_MSG_CHANNEL_OPEN;
extern const uint8_t SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
extern const uint8_t SSH_MSG_CHANNEL_OPEN_FAILURE;
extern const uint8_t SSH_MSG_CHANNEL_WINDOW_ADJUST;
extern const uint8_t SSH_MSG_CHANNEL_DATA;
extern const uint8_t SSH_MSG_CHANNEL_EXTENDED_DATA;
extern const uint8_t SSH_MSG_CHANNEL_EOF;
extern const uint8_t SSH_MSG_CHANNEL_CLOSE;
extern const uint8_t SSH_MSG_CHANNEL_REQUEST;
extern const uint8_t SSH_MSG_CHANNEL_SUCCESS;
extern const uint8_t SSH_MSG_CHANNEL_FAILURE;

/* SSH disconnect reason codes, as defined in rfc4250§4.2.2 */
extern const uint8_t SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT;
extern const uint8_t SSH_DISCONNECT_PROTOCOL_ERROR;
extern const uint8_t SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
extern const uint8_t SSH_DISCONNECT_RESERVED;
extern const uint8_t SSH_DISCONNECT_MAC_ERROR;
extern const uint8_t SSH_DISCONNECT_COMPRESSION_ERROR;
extern const uint8_t SSH_DISCONNECT_SERVICE_NOT_AVAILABLE;
extern const uint8_t SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED;
extern const uint8_t SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE;
extern const uint8_t SSH_DISCONNECT_CONNECTION_LOST;
extern const uint8_t SSH_DISCONNECT_BY_APLICATION;
extern const uint8_t SSH_DISCONNECT_TOO_MANY_CONNECTIONS;
extern const uint8_t SSH_DISCONNECT_AUTH_CANCELLED_BY_USER;
extern const uint8_t SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE;
extern const uint8_t SSH_DISCONNECT_ILLEGAL_USER_NAME;

/* The bytes for the prime defining dh group 14 (in reverse order),
 * as defined in rfc3526 */
extern const uint8_t DH_14_BLOCKS[256];

extern const uint8_t MYSSH_AUTH_SUCCESS;
extern const uint8_t MYSSH_AUTH_FAIL;
extern const uint8_t MYSSH_AUTH_REDO;

#endif
