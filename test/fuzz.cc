/*
 * Copyright © 2018 Mozilla Foundation
 *
 * This program is made available under an ISC-style license.  See the
 * accompanying file LICENSE for details.
 */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "nestegg/nestegg.h"

/* fuzz.cc is meant to be used with LibFuzzer
 * (https://llvm.org/docs/LibFuzzer.html)
 *
 * To build:
 * clang -g -O1 -fsanitize=fuzzer -I./include src/nestegg.c test/fuzz.cc -o fuzz
 *
 * NOTE: At the moment there are large chunks of code that have been copied
 *       from regress.c
 */

/* Three functions that implement the nestegg_io interface, operating on a
   io_buffer. */
struct io_buffer {
  unsigned char const * buffer;
  size_t length;
  int64_t offset;
};

static int
ne_buffer_read(void * buffer, size_t length, void * userdata)
{
  struct io_buffer * iob = reinterpret_cast<struct io_buffer *>(userdata);
  size_t available = iob->length - iob->offset;

  if (available == 0)
    return 0;

  if (available < length)
    return -1;

  memcpy(buffer, iob->buffer + iob->offset, length);
  iob->offset += length;

  return 1;
}

static int
ne_buffer_seek(int64_t offset, int whence, void * userdata)
{
  struct io_buffer * iob = reinterpret_cast<struct io_buffer *>(userdata);
  int64_t o = iob->offset;

  switch(whence) {
  case NESTEGG_SEEK_SET:
    o = offset;
    break;
  case NESTEGG_SEEK_CUR:
    o += offset;
    break;
  case NESTEGG_SEEK_END:
    o = iob->length + offset;
    break;
  }

  if (o < 0 || o > (int64_t) iob->length)
    return -1;

  iob->offset = o;
  return 0;
}

static int64_t
ne_buffer_tell(void * userdata)
{
  struct io_buffer * iob = reinterpret_cast<struct io_buffer *>(userdata);
  return iob->offset;
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  int r, type, id, track_encoding, pkt_keyframe, pkt_encryption, cues;
  int64_t read_limit = -1;
  nestegg * ctx;
  nestegg_audio_params aparams;
  nestegg_packet * pkt;
  nestegg_video_params vparams;
  size_t length;
  uint64_t duration = ~0, pkt_tstamp, pkt_duration, tstamp_scale, default_duration;
  int64_t pkt_discard_padding, pkt_reference_block;
  unsigned char * codec_data, * ptr, * pkt_additional;
  unsigned char const * track_content_enc_key_id, * pkt_encryption_iv;
  unsigned int i, j, tracks = 0, pkt_cnt, pkt_track;
  unsigned int data_items = 0;
  uint8_t pkt_num_offsets;
  uint32_t const * pkt_partition_offsets;

  nestegg_io io;
  struct io_buffer userdata;
  userdata.buffer = data;
  userdata.length = size;
  userdata.offset = 0;

  io.read = ne_buffer_read;
  io.seek = ne_buffer_seek;
  io.tell = ne_buffer_tell;
  io.userdata = &userdata;

  ctx = NULL;
  r = nestegg_init(&ctx, io, NULL, read_limit);
  if (r != 0)
    return 0;

  nestegg_track_count(ctx, &tracks);
  nestegg_duration(ctx, &duration);
  nestegg_tstamp_scale(ctx, &tstamp_scale);
  cues = nestegg_has_cues(ctx);

  for (i = 0; i < tracks; ++i) {
    type = nestegg_track_type(ctx, i);
    id = nestegg_track_codec_id(ctx, i);
    nestegg_track_codec_data_count(ctx, i, &data_items);
    track_encoding = nestegg_track_encoding(ctx, i);
    r = nestegg_track_default_duration(ctx, i, &default_duration);
    if (track_encoding == NESTEGG_ENCODING_ENCRYPTION) {
      nestegg_track_content_enc_key_id(ctx, i, &track_content_enc_key_id, &length);
    }
    for (j = 0; j < data_items; ++j) {
      nestegg_track_codec_data(ctx, i, j, &codec_data, &length);
    }
    switch (type) {
    case NESTEGG_TRACK_VIDEO:
      nestegg_track_video_params(ctx, i, &vparams);
      break;
    case NESTEGG_TRACK_AUDIO:
      nestegg_track_audio_params(ctx, i, &aparams);
      break;
    //case NESTEGG_TRACK_UNKNOWN:
    //  break;
    default:
      break;
    }
  }

  for (;;) {
    pkt = NULL;
    r = nestegg_read_packet(ctx, &pkt);
    if (r <= 0) {
      assert(pkt == NULL);
      break;
    }
    nestegg_packet_track(pkt, &pkt_track);
    pkt_keyframe = nestegg_packet_has_keyframe(pkt);
    nestegg_packet_count(pkt, &pkt_cnt);
    nestegg_packet_tstamp(pkt, &pkt_tstamp);
    pkt_duration = 0;
    nestegg_packet_duration(pkt, &pkt_duration);
    pkt_discard_padding = 0;
    nestegg_packet_discard_padding(pkt, &pkt_discard_padding);
    pkt_reference_block = 0;
    nestegg_packet_reference_block(pkt, &pkt_reference_block);
    pkt_additional = NULL;
    nestegg_packet_additional_data(pkt, 1, &pkt_additional, &length);
    pkt_encryption = nestegg_packet_encryption(pkt);
    if (pkt_encryption == NESTEGG_PACKET_HAS_SIGNAL_BYTE_ENCRYPTED ||
        pkt_encryption == NESTEGG_PACKET_HAS_SIGNAL_BYTE_PARTITIONED) {
      nestegg_packet_iv(pkt, &pkt_encryption_iv, &length);
    }
    if (pkt_encryption == NESTEGG_PACKET_HAS_SIGNAL_BYTE_PARTITIONED) {
      nestegg_packet_offsets(pkt, &pkt_partition_offsets, &pkt_num_offsets);
    }
    for (i = 0; i < pkt_cnt; ++i) {
      nestegg_packet_data(pkt, i, &ptr, &length);
    }
    nestegg_free_packet(pkt);
  }

  nestegg_destroy(ctx);
  return 0;
}
