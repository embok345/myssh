#ifndef MYSSH_NUMBERS_H
#define MYSSH_NUMBERS_H

extern const uint8_t SSH_MSG_DISCONNECT;
extern const uint8_t SSH_MSG_IGNORE;
extern const uint8_t SSH_MSG_UNIMPLEMENTED;
extern const uint8_t SSH_MSG_DEBUG;
extern const uint8_t SSH_MSG_SERVICE_REQUEST;
extern const uint8_t SSH_SERVICE_ACCEPT;
extern const uint8_t SSH_MSG_KEXINIT;
extern const uint8_t SSH_MSG_NEWKEYS;
extern const uint8_t SSH_MSG_KEXDH_INIT;
extern const uint8_t SSH_MSG_KEXDH_REPLY;
extern const uint8_t SSH_MSG_USERAUTH_REQUEST;
extern const uint8_t SSH_MSG_USERAUTH_FAILURE;
extern const uint8_t SSH_MSG_USERAUTH_SUCCESS;
extern const uint8_t SSH_MSG_USERAUTH_BANNER;
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

extern const uint8_t DH_14_BLOCKS[256];

#endif
