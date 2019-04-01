#include "myssh.h"

void *global_request_listener(void *arg) {
  connection *c = (connection *)arg;
  while(1) {
    packet global_request = wait_for_packet(c, 1, SSH_MSG_GLOBAL_REQUEST);
    //TODO actually do something with this
    printf("Got global request\n");
    free_pak(&global_request);
  }
}

void *reader_listener(void *arg) {
  connection *c = (connection *)arg;

  while(1) {

    pthread_mutex_lock(&(c->pak.mutex));

    //Read the first few bytes on the socket, to get the total length
    uint32_t block_size;
    if(!c->enc_s2c)
      //If the session isn't encrypted, just read 8 bytes (min length)
      block_size = 8;
    else
      //Otherwise read the blocksize of the encryption
      block_size = c->enc_s2c->block_size;
    byte_array_t first_block;
    first_block.len = block_size;
    first_block.arr = malloc(first_block.len);
    if(recv(c->socket, first_block.arr, first_block.len, 0) < block_size) {
      //If we don't receive the right number of bytes, there's an error
      printf("Received fewer than expected bytes\n");
      return NULL;
    }

    byte_array_t read, temp;
    if(c->enc_s2c) {
      //If there is encryption, try to decrypt the first block
      if(c->enc_s2c->dec(first_block, c->enc_s2c->key, &(c->enc_s2c->iv),
          &temp) != 0) {
        printf("Error when decrypting\n");
        return NULL;
      }
      read.len = temp.len;
      read.arr = malloc(read.len);
      memcpy(read.arr, temp.arr, read.len);
      free(temp.arr);
    } else {
      //Otherwise just copy the read bytes in
      read.len = first_block.len;
      read.arr = malloc(read.len);
      memcpy(read.arr, first_block.arr, read.len);
    }
    free(first_block.arr);

    //Initialise the packet with the packet length and padding length,
    //malloc the spaces for the payload and padding
    c->pak.p = malloc(sizeof(packet));
    c->pak.p->packet_length = bytes_to_int(read.arr);
    c->pak.p->padding_length = (read.arr)[4];
    if((c->pak.p->packet_length + 4)%block_size != 0) {
      //Length of the packet must be a multiple of the block size
      printf("Invalid message length\n");
      return NULL; //TODO something else
    }
    c->pak.p->payload.len = c->pak.p->packet_length -
        c->pak.p->padding_length - 1;
    c->pak.p->payload.arr = malloc(c->pak.p->payload.len);
    c->pak.p->padding = malloc(c->pak.p->padding_length);

    int to_receive = c->pak.p->packet_length + 4 - block_size;
    if(to_receive >= 35000 || to_receive < 0) {
      //The maximum packet size is 35000 bytes.
      //Obviously there should be a non-negative number of bytes still to read.
      printf("Invalid message length\n");
      return NULL;
    }

    if(to_receive > 0) {
      //Receive the rest of the packet
      byte_array_t next_blocks;
      next_blocks.len = to_receive;
      next_blocks.arr = malloc(to_receive);
      if(recv(c->socket, next_blocks.arr, to_receive, 0) < to_receive) {
        printf("Received fewer than expected bytes\n");
        return NULL;
      }

      //Decrypt the new blocks
      if(c->enc_s2c) {
        if(c->enc_s2c->dec(next_blocks, c->enc_s2c->key, &(c->enc_s2c->iv),
            &temp) != 0) {
          printf("Error when decrypting\n");
          return NULL;
        }
        read.len += temp.len;
        read.arr = realloc(read.arr, read.len);
        memcpy(read.arr + first_block.len, temp.arr,
            read.len - first_block.len);
        free(temp.arr);
      } else {
        read.len += next_blocks.len;
        read.arr = realloc(read.arr, read.len);
        memcpy(read.arr + first_block.len, next_blocks.arr,
            read.len - first_block.len);
      }

      free(next_blocks.arr);
    }

    //Copy the decrypted bytes into the packet.
    //We could do this directly but the offsets and such may be tricky
    memcpy(c->pak.p->payload.arr, read.arr + 5, c->pak.p->payload.len);
    memcpy(c->pak.p->padding, read.arr + 5 + c->pak.p->payload.len,
        c->pak.p->padding_length);

    //If there is a mac, get those blocks.
    if(c->mac_s2c) {
      read.len += c->mac_s2c->mac_output_size;
      read.arr = realloc(read.arr, read.len);
      if(recv(c->socket, read.arr + read.len - c->mac_s2c->mac_output_size,
          c->mac_s2c->mac_output_size, 0) < c->mac_s2c->mac_output_size) {
        printf("Received fewer than expected MAC bytes\n");
        return NULL;
      }
      //TODO we should check if the mac is the same
      c->pak.p->mac.len = c->mac_s2c->mac_output_size;
      c->pak.p->mac.arr = malloc(c->mac_s2c->mac_output_size);
      memcpy(c->pak.p->mac.arr, read.arr + read.len - c->mac_s2c->mac_output_size,
          c->mac_s2c->mac_output_size);
    } else {
      c->pak.p->mac.len = 0;
      c->pak.p->mac.arr = NULL;
    }

    free(read.arr);

    pthread_cond_broadcast(&(c->pak.packet_present));
    while(c->pak.p) {
      pthread_cond_wait(&(c->pak.packet_handled), &(c->pak.mutex));
    }
    pthread_mutex_unlock(&(c->pak.mutex));
  }
}
