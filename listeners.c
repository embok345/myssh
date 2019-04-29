#include "myssh.h"

void *channel_listener(void *args) {
  struct stuff {connection *c; uint32_t channel;} *arg =
      (struct stuff *)args;
  connection *c = arg->c;
  uint32_t channel = arg->channel;
  while(1) {
    packet message = wait_for_channel_packet(c, channel);
    char *msg_str = NULL, *command = NULL;
    if(get_byteArray_element(message.payload, 0) == SSH_MSG_CHANNEL_DATA) {
      uint32_t message_length = byteArray_to_int(message.payload, 5);
      msg_str = realloc(msg_str, message_length + 1);
      //strncpy(msg_str, message.payload.arr + 9, message_length);
      byteArray_strncpy(msg_str, message.payload, 9, message_length);
      //msg_str[message_length] = '\0';
      command = realloc(command, strlen(msg_str) + 11);
      sprintf(command, "echo -n \"%s\"", msg_str);
      system(command);
    }
    free_pak(message);
  }
}

packet wait_for_channel_packet(connection *c, uint32_t channel) {
  packet received_packet;
  _byte_array_t codes = create_byteArray(10);
  for(int i=0; i<10; i++) {
    set_byteArray_element(codes, i, 91+i);
  }
  while(1) {
    //Acquire the lock, and check if there is a packet present
    pthread_mutex_lock(&(c->pak.mutex));
    while(!(c->pak.p)) {
      //Wait until a packet arrives
      pthread_cond_wait(&(c->pak.packet_present), &(c->pak.mutex));
    }
    //We now own the lock, and a packet is present
    //if(c->pak.p->payload.len < 5 ||
    //    !byteArray_contains(codes, c->pak.p->payload.arr[0]) ||
    //    bytes_to_int(c->pak.p->payload.arr + 1) != channel) {
    if(get_byteArray_len(c->pak.p->payload) < 5 ||
        !byteArray_contains(codes, get_byteArray_element(c->pak.p->payload, 0)) ||
        byteArray_to_int(c->pak.p->payload, 1) != channel) {
      //If we can't get a code, or the code is not the one we
      //want, wait till this packet is handled
      pthread_cond_wait(&(c->pak.packet_handled), &(c->pak.mutex));
      pthread_mutex_unlock(&(c->pak.mutex));
    } else {
      //If we have the message we want, copy it out
      received_packet = clone_pak(*(c->pak.p));
      free_pak(*(c->pak.p));
      free(c->pak.p);
      c->pak.p = NULL;
      //Let the listener know we're done with the packet
      pthread_cond_broadcast(&(c->pak.packet_handled));
      pthread_mutex_unlock(&(c->pak.mutex));
      free_byteArray(codes);
      return received_packet;
    }
  }
}

packet wait_for_packet(connection *c, int no_codes, ...) {
  packet received_packet;
  _byte_array_t codes;
  if(no_codes == 0) {
    codes = create_byteArray(256);
    for(int i=0; i<256; i++) {
      set_byteArray_element(codes, i, i);
    }
  } else {
    codes = create_byteArray(no_codes);
    va_list valist;
    va_start(valist, no_codes);
    for(int i=0; i<no_codes; i++)
      set_byteArray_element(codes, i, va_arg(valist, int));
    va_end(valist);
  }

  while(1) {
    //Acquire the lock, and check if there is a packet present
    pthread_mutex_lock(&(c->pak.mutex));
    while(!(c->pak.p)) {
      //Wait until a packet arrives
      pthread_cond_wait(&(c->pak.packet_present), &(c->pak.mutex));
    }
    //We now own the lock, and a packet is present
    if(get_byteArray_len(c->pak.p->payload) < 1 ||
        !byteArray_contains(codes, get_byteArray_element(c->pak.p->payload,0))) {
      //If we can't get a code, or the code is not the one we
      //want, wait till this packet is handled
      pthread_cond_wait(&(c->pak.packet_handled), &(c->pak.mutex));
      pthread_mutex_unlock(&(c->pak.mutex));
    } else {
      //If we have the message we want, copy it out
      received_packet = clone_pak(*(c->pak.p));
      free_pak(*(c->pak.p));
      free(c->pak.p);
      c->pak.p = NULL;
      //Let the listener know we're done with the packet
      pthread_cond_broadcast(&(c->pak.packet_handled));
      pthread_mutex_unlock(&(c->pak.mutex));
      free_byteArray(codes);
      return received_packet;
    }
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
    _byte_array_t first_block;
    //first_block.len = block_size;
    //first_block.arr = malloc(first_block.len);
    uint32_t recvd_bytes;
    if((recvd_bytes = recv_byteArray(c->socket, &first_block, block_size))
        < block_size) {
      //If we don't receive the right number of bytes, there's an error
      FILE *log = fopen(LOG_NAME, "a");
      fprintf(log, "Received fewer than expected bytes:");
      fprintf(log, "Expected %"PRIu32" but got %"PRIu32"\n", block_size,
          recvd_bytes);
      fclose(log);
      //return NULL;
      exit(1);
    }

    _byte_array_t read, temp;
    if(c->enc_s2c) {
      //If there is encryption, try to decrypt the first block
      if(c->enc_s2c->dec(first_block, c->enc_s2c->key, c->enc_s2c->iv,
          &temp) != 0) {
        printf("Error when decrypting\n");
        return NULL;
      }
      //read.len = temp.len;
      //read.arr = malloc(read.len);
      //memcpy(read.arr, temp.arr, read.len);
      //free(temp.arr);
      read = copy_byteArray(temp);
      free_byteArray(temp);
    } else {
      //Otherwise just copy the read bytes in
      //read.len = first_block.len;
      //read.arr = malloc(read.len);
      //memcpy(read.arr, first_block.arr, read.len);
      read = copy_byteArray(first_block);
    }
    free_byteArray(first_block);

    //Initialise the packet with the packet length and padding length,
    //malloc the spaces for the payload and padding
    c->pak.p = malloc(sizeof(packet));
    c->pak.p->packet_length = byteArray_to_int(read, 0);
    c->pak.p->padding_length = get_byteArray_element(read, 4);
    if((c->pak.p->packet_length + 4)%block_size != 0) {
      //Length of the packet must be a multiple of the block size
      printf("Invalid message length\n");
      return NULL; //TODO something else
    }
    //c->pak.p->payload.len = c->pak.p->packet_length -
    //    c->pak.p->padding_length - 1;
    //c->pak.p->payload.arr = malloc(c->pak.p->payload.len);
    //c->pak.p->payload = create_byteArray(c->pak.p->packet_length -
    //    c->pak.p->padding_length - 1);
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
      //byte_array_t next_blocks;
      //next_blocks.len = to_receive;
      //next_blocks.arr = malloc(to_receive);
      _byte_array_t next_blocks;
      if(recv_byteArray(c->socket, &next_blocks, to_receive) < to_receive) {
        printf("Received fewer than expected bytes\n");
        return NULL;
      }

      //Decrypt the new blocks
      if(c->enc_s2c) {
        if(c->enc_s2c->dec(next_blocks, c->enc_s2c->key, c->enc_s2c->iv,
            &temp) != 0) {
          printf("Error when decrypting\n");
          return NULL;
        }
        byteArray_append_byteArray(read, temp);
        //read.len += temp.len;
        //read.arr = realloc(read.arr, read.len);
        //memcpy(read.arr + first_block.len, temp.arr,
        //    read.len - first_block.len);
        free_byteArray(temp);
      } else {
        //read.len += next_blocks.len;
        //read.arr = realloc(read.arr, read.len);
        //memcpy(read.arr + first_block.len, next_blocks.arr,
        //    read.len - first_block.len);
        byteArray_append_byteArray(read, next_blocks);
      }

      free_byteArray(next_blocks);
    }

    //Copy the decrypted bytes into the packet.
    //We could do this directly but the offsets and such may be tricky
    //memcpy(c->pak.p->payload.arr, read.arr + 5, c->pak.p->payload.len);
    c->pak.p->payload = sub_byteArray(read, 5, c->pak.p->packet_length -
        c->pak.p->padding_length - 1);
    //memcpy(c->pak.p->padding, read.arr + 5 + c->pak.p->payload.len,
    //    c->pak.p->padding_length);
    byteArray_strncpy(c->pak.p->padding, read, 5 + get_byteArray_len(c->pak.p->payload),
        c->pak.p->padding_length);

    //If there is a mac, get those blocks.
    if(c->mac_s2c) {
      if(recv_byteArray(c->socket, &(c->pak.p->mac), c->mac_s2c->mac_output_size)
          < c->mac_s2c->mac_output_size) {
        printf("Received fewer than expected MAC bytes\n");
        return NULL;
      }
    } else {
      c->pak.p->mac = create_byteArray(0);
    }

    free_byteArray(read);

    uint8_t code = get_byteArray_element(c->pak.p->payload, 0);
    if(code == SSH_MSG_DISCONNECT) {
      return NULL;
    } else if(code == SSH_MSG_IGNORE) {
      free_pak(*(c->pak.p));
      free(c->pak.p);
      c->pak.p = NULL;
      pthread_mutex_unlock(&(c->pak.mutex));
    } else if(code == SSH_MSG_UNIMPLEMENTED) {
      free_pak(*(c->pak.p));
      free(c->pak.p);
      c->pak.p = NULL;
      pthread_mutex_unlock(&(c->pak.mutex));
    } else if(code == SSH_MSG_DEBUG) {
      free_pak(*(c->pak.p));
      free(c->pak.p);
      c->pak.p = NULL;
      pthread_mutex_unlock(&(c->pak.mutex));
    } else if(code == SSH_MSG_GLOBAL_REQUEST) {
      free_pak(*(c->pak.p));
      free(c->pak.p);
      c->pak.p = NULL;
      pthread_mutex_unlock(&(c->pak.mutex));
    } else {
      pthread_cond_broadcast(&(c->pak.packet_present));
      while(c->pak.p) {
        pthread_cond_wait(&(c->pak.packet_handled), &(c->pak.mutex));
      }
      pthread_mutex_unlock(&(c->pak.mutex));
    }
  }
}

void start_reader(connection *c) {
  pthread_t reader;
  pthread_create(&reader, NULL, reader_listener, (void *)c);
}
