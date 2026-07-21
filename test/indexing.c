/*
 * Copyright © 2026 Mozilla Foundation
 *
 * This program is made available under an ISC-style license.  See the
 * accompanying file LICENSE for details.
 */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nestegg/nestegg.h"

#define TEST_TRACK_LIMIT 1000U

#define ID_EBML                 0x1a45dfa3U
#define ID_EBML_READ_VERSION    0x42f7U
#define ID_DOCTYPE              0x4282U
#define ID_DOCTYPE_READ_VERSION 0x4285U
#define ID_SEGMENT              0x18538067U
#define ID_TRACKS               0x1654ae6bU
#define ID_TRACK_ENTRY          0xaeU
#define ID_TRACK_NUMBER         0xd7U
#define ID_TRACK_UID            0x73c5U
#define ID_TRACK_TYPE           0x83U
#define ID_CODEC_ID             0x86U
#define ID_CUES                 0x1c53bb6bU
#define ID_CUE_POINT            0xbbU
#define ID_CUE_TIME             0xb3U
#define ID_CUE_TRACK_POSITIONS  0xb7U
#define ID_CUE_TRACK            0xf7U
#define ID_CUE_CLUSTER_POSITION 0xf1U
#define ID_CLUSTER              0x1f43b675U
#define ID_TIMECODE             0xe7U
#define ID_SIMPLE_BLOCK         0xa3U

struct buffer {
  unsigned char * data;
  size_t length;
  size_t capacity;
};

struct buffer_io {
  unsigned char const * data;
  size_t length;
  size_t offset;
};

static void
buffer_reserve(struct buffer * buffer, size_t extra)
{
  size_t required;
  size_t capacity;
  unsigned char * data;

  assert(extra <= (size_t) -1 - buffer->length);
  required = buffer->length + extra;
  if (required <= buffer->capacity)
    return;

  capacity = buffer->capacity ? buffer->capacity : 256;
  while (capacity < required) {
    assert(capacity <= (size_t) -1 / 2);
    capacity *= 2;
  }

  data = realloc(buffer->data, capacity);
  assert(data);
  buffer->data = data;
  buffer->capacity = capacity;
}

static void
buffer_put(struct buffer * buffer, void const * data, size_t length)
{
  buffer_reserve(buffer, length);
  memcpy(buffer->data + buffer->length, data, length);
  buffer->length += length;
}

static void
buffer_put_byte(struct buffer * buffer, unsigned char value)
{
  buffer_put(buffer, &value, 1);
}

static void
buffer_put_be(struct buffer * buffer, uint64_t value, unsigned int width)
{
  unsigned int i;

  for (i = width; i > 0; --i)
    buffer_put_byte(buffer, (unsigned char) (value >> ((i - 1) * 8)));
}

static void
buffer_put_id(struct buffer * buffer, uint32_t id)
{
  unsigned int width;

  if (id > 0xffffffU)
    width = 4;
  else if (id > 0xffffU)
    width = 3;
  else if (id > 0xffU)
    width = 2;
  else
    width = 1;

  buffer_put_be(buffer, id, width);
}

static void
buffer_put_size(struct buffer * buffer, size_t size)
{
  uint64_t limit;
  uint64_t encoded;
  unsigned int width;

  for (width = 1; width <= 8; ++width) {
    limit = (UINT64_C(1) << (7 * width)) - 1;
    if (size < limit)
      break;
  }
  assert(width <= 8);

  encoded = (uint64_t) size | (UINT64_C(1) << (7 * width));
  buffer_put_be(buffer, encoded, width);
}

static void
buffer_put_vint(struct buffer * buffer, uint64_t value)
{
  uint64_t limit;
  uint64_t encoded;
  unsigned int width;

  for (width = 1; width <= 8; ++width) {
    limit = (UINT64_C(1) << (7 * width)) - 1;
    if (value < limit)
      break;
  }
  assert(width <= 8);

  encoded = value | (UINT64_C(1) << (7 * width));
  buffer_put_be(buffer, encoded, width);
}

static void
buffer_put_master(struct buffer * buffer, uint32_t id,
                  struct buffer const * payload)
{
  buffer_put_id(buffer, id);
  buffer_put_size(buffer, payload->length);
  buffer_put(buffer, payload->data, payload->length);
}

static void
buffer_put_uint(struct buffer * buffer, uint32_t id, uint64_t value)
{
  unsigned int width = 1;

  while (width < 8 && value >= (UINT64_C(1) << (width * 8)))
    width += 1;

  buffer_put_id(buffer, id);
  buffer_put_size(buffer, width);
  buffer_put_be(buffer, value, width);
}

static void
buffer_put_string(struct buffer * buffer, uint32_t id, char const * value)
{
  size_t length = strlen(value);

  buffer_put_id(buffer, id);
  buffer_put_size(buffer, length);
  buffer_put(buffer, value, length);
}

static void
buffer_clear(struct buffer * buffer)
{
  buffer->length = 0;
}

static void
buffer_destroy(struct buffer * buffer)
{
  free(buffer->data);
  memset(buffer, 0, sizeof(*buffer));
}

static void
put_ebml_header(struct buffer * file)
{
  struct buffer payload = { 0 };

  buffer_put_uint(&payload, ID_EBML_READ_VERSION, 1);
  buffer_put_string(&payload, ID_DOCTYPE, "webm");
  buffer_put_uint(&payload, ID_DOCTYPE_READ_VERSION, 2);
  buffer_put_master(file, ID_EBML, &payload);
  buffer_destroy(&payload);
}

static void
put_track_entry(struct buffer * tracks, uint64_t number)
{
  struct buffer entry = { 0 };

  buffer_put_uint(&entry, ID_TRACK_NUMBER, number);
  buffer_put_uint(&entry, ID_TRACK_UID, number);
  buffer_put_uint(&entry, ID_TRACK_TYPE, 1);
  buffer_put_string(&entry, ID_CODEC_ID, "V_VP8");
  buffer_put_master(tracks, ID_TRACK_ENTRY, &entry);
  buffer_destroy(&entry);
}

static void
put_tracks(struct buffer * element, uint64_t const * numbers,
           unsigned int count)
{
  struct buffer payload = { 0 };
  unsigned int i;

  for (i = 0; i < count; ++i)
    put_track_entry(&payload, numbers ? numbers[i] : i + 1);

  buffer_put_master(element, ID_TRACKS, &payload);
  buffer_destroy(&payload);
}

static void
put_cues(struct buffer * element, uint64_t const * numbers,
         unsigned int count, uint64_t cluster_position)
{
  struct buffer cues = { 0 };
  struct buffer point = { 0 };
  unsigned int i;

  buffer_put_uint(&point, ID_CUE_TIME, 0);
  for (i = 0; i < count; ++i) {
    struct buffer position = { 0 };

    buffer_put_uint(&position, ID_CUE_TRACK, numbers[i]);
    buffer_put_uint(&position, ID_CUE_CLUSTER_POSITION, cluster_position);
    buffer_put_master(&point, ID_CUE_TRACK_POSITIONS, &position);
    buffer_destroy(&position);
  }

  buffer_put_master(&cues, ID_CUE_POINT, &point);
  buffer_put_master(element, ID_CUES, &cues);
  buffer_destroy(&point);
  buffer_destroy(&cues);
}

static void
put_simple_block(struct buffer * cluster, uint64_t track_number,
                 unsigned char flags, unsigned int frames)
{
  struct buffer block = { 0 };
  unsigned int i;

  assert(frames >= 1 && frames <= 256);
  buffer_put_vint(&block, track_number);
  buffer_put_byte(&block, 0);
  buffer_put_byte(&block, 0);
  buffer_put_byte(&block, flags);

  if (frames > 1)
    buffer_put_byte(&block, (unsigned char) (frames - 1));

  for (i = 0; i < frames; ++i)
    buffer_put_byte(&block, (unsigned char) i);

  buffer_put_master(cluster, ID_SIMPLE_BLOCK, &block);
  buffer_destroy(&block);
}

static void
put_test_cluster(struct buffer * element, uint64_t large_track_number)
{
  struct buffer cluster = { 0 };

  buffer_put_uint(&cluster, ID_TIMECODE, 0);
  put_simple_block(&cluster, large_track_number, 0x80, 1);
  put_simple_block(&cluster, 1, 0x84, 256);
  buffer_put_master(element, ID_CLUSTER, &cluster);
  buffer_destroy(&cluster);
}

static void
build_track_file(struct buffer * file, uint64_t const * numbers,
                 unsigned int count)
{
  struct buffer segment = { 0 };
  struct buffer tracks = { 0 };
  struct buffer cluster = { 0 };
  struct buffer cluster_payload = { 0 };

  put_tracks(&tracks, numbers, count);
  buffer_put_master(&cluster, ID_CLUSTER, &cluster_payload);

  buffer_put(&segment, tracks.data, tracks.length);
  buffer_put(&segment, cluster.data, cluster.length);

  put_ebml_header(file);
  buffer_put_master(file, ID_SEGMENT, &segment);

  buffer_destroy(&cluster);
  buffer_destroy(&cluster_payload);
  buffer_destroy(&tracks);
  buffer_destroy(&segment);
}

static void
build_indexed_file(struct buffer * file, uint64_t const * numbers,
                   unsigned int count)
{
  struct buffer tracks = { 0 };
  struct buffer cues = { 0 };
  struct buffer cluster = { 0 };
  struct buffer segment = { 0 };
  size_t old_position;
  size_t cluster_position = 0;

  put_tracks(&tracks, numbers, count);
  put_test_cluster(&cluster, numbers[count - 1]);

  do {
    old_position = cluster_position;
    buffer_clear(&cues);
    put_cues(&cues, numbers, count, cluster_position);
    cluster_position = tracks.length + cues.length;
  } while (cluster_position != old_position);

  buffer_put(&segment, tracks.data, tracks.length);
  buffer_put(&segment, cues.data, cues.length);
  buffer_put(&segment, cluster.data, cluster.length);

  put_ebml_header(file);
  buffer_put_master(file, ID_SEGMENT, &segment);

  buffer_destroy(&segment);
  buffer_destroy(&cluster);
  buffer_destroy(&cues);
  buffer_destroy(&tracks);
}

static int64_t
memory_read(void * destination, size_t length, void * userdata)
{
  struct buffer_io * io = userdata;
  size_t available = io->length - io->offset;

  if (length > available)
    length = available;
  if (length == 0)
    return 0;

  memcpy(destination, io->data + io->offset, length);
  io->offset += length;
  return (int64_t) length;
}

static int
memory_seek(int64_t offset, int whence, void * userdata)
{
  struct buffer_io * io = userdata;
  int64_t position;

  if (whence == NESTEGG_SEEK_SET)
    position = offset;
  else if (whence == NESTEGG_SEEK_CUR)
    position = (int64_t) io->offset + offset;
  else if (whence == NESTEGG_SEEK_END)
    position = (int64_t) io->length + offset;
  else
    return -1;

  if (position < 0 || (uint64_t) position > io->length)
    return -1;

  io->offset = (size_t) position;
  return 0;
}

static int64_t
memory_tell(void * userdata)
{
  struct buffer_io * io = userdata;
  return (int64_t) io->offset;
}

static int
init_from_buffer(nestegg ** context, struct buffer const * file,
                 struct buffer_io * userdata)
{
  nestegg_io io;

  userdata->data = file->data;
  userdata->length = file->length;
  userdata->offset = 0;

  memset(&io, 0, sizeof(io));
  io.read = memory_read;
  io.seek = memory_seek;
  io.tell = memory_tell;
  io.userdata = userdata;
  return nestegg_init(context, io, NULL, -1);
}

static void
test_track_limit(void)
{
  struct buffer file = { 0 };
  struct buffer_io userdata;
  nestegg * context = NULL;
  unsigned int tracks;
  unsigned int i;
  int r;

  build_track_file(&file, NULL, TEST_TRACK_LIMIT);
  r = init_from_buffer(&context, &file, &userdata);
  assert(r == 0);
  assert(nestegg_track_count(context, &tracks) == 0);
  assert(tracks == TEST_TRACK_LIMIT);
  for (i = 0; i < tracks; ++i) {
    assert(nestegg_track_type(context, i) == NESTEGG_TRACK_VIDEO);
    assert(nestegg_track_codec_id(context, i) == NESTEGG_CODEC_VP8);
  }
  assert(nestegg_track_type(context, tracks) == -1);
  nestegg_destroy(context);
  buffer_destroy(&file);

  context = NULL;
  build_track_file(&file, NULL, TEST_TRACK_LIMIT + 1);
  r = init_from_buffer(&context, &file, &userdata);
  assert(r == -1);
  assert(context == NULL);
  buffer_destroy(&file);
}

static void
test_invalid_track_numbers(void)
{
  uint64_t duplicate_numbers[] = { 1, 1 };
  uint64_t zero_number[] = { 0 };
  struct buffer file = { 0 };
  struct buffer_io userdata;
  nestegg * context = NULL;

  build_track_file(&file, duplicate_numbers, 2);
  assert(init_from_buffer(&context, &file, &userdata) == -1);
  assert(context == NULL);
  buffer_destroy(&file);

  build_track_file(&file, zero_number, 1);
  assert(init_from_buffer(&context, &file, &userdata) == -1);
  assert(context == NULL);
  buffer_destroy(&file);
}

static void
test_indexed_access(void)
{
  uint64_t numbers[] = { 1, 17, UINT64_C(0x100000001) };
  struct buffer file = { 0 };
  struct buffer_io userdata;
  nestegg * context = NULL;
  nestegg_packet * packet = NULL;
  unsigned char * data;
  size_t length;
  unsigned int count;
  unsigned int track;
  unsigned int i;
  int64_t start;
  int64_t end;
  uint64_t timestamp;

  build_indexed_file(&file, numbers, 3);
  assert(init_from_buffer(&context, &file, &userdata) == 0);

  assert(nestegg_track_count(context, &count) == 0);
  assert(count == 3);
  for (i = 0; i < count; ++i) {
    assert(nestegg_track_type(context, i) == NESTEGG_TRACK_VIDEO);
    assert(nestegg_track_codec_id(context, i) == NESTEGG_CODEC_VP8);
  }
  assert(nestegg_track_codec_id(context, count) == -1);

  assert(nestegg_get_cue_point(context, 0, -1, &start, &end,
                               &timestamp) == 0);
  assert(start >= 0);
  assert(timestamp == 0);

  assert(nestegg_read_packet(context, &packet) == 1);
  assert(nestegg_packet_track(packet, &track) == 0);
  assert(track == 2);
  assert(nestegg_packet_count(packet, &count) == 0);
  assert(count == 1);
  assert(nestegg_packet_data(packet, 0, &data, &length) == 0);
  assert(length == 1 && data[0] == 0);
  nestegg_free_packet(packet);

  packet = NULL;
  assert(nestegg_read_packet(context, &packet) == 1);
  assert(nestegg_packet_track(packet, &track) == 0);
  assert(track == 0);
  assert(nestegg_packet_count(packet, &count) == 0);
  assert(count == 256);
  for (i = 0; i < count; ++i) {
    assert(nestegg_packet_data(packet, i, &data, &length) == 0);
    assert(length == 1 && data[0] == (unsigned char) i);
  }
  data = (unsigned char *) 1;
  length = 1;
  assert(nestegg_packet_data(packet, count, &data, &length) == -1);
  assert(data == NULL && length == 0);
  nestegg_free_packet(packet);

  assert(nestegg_track_seek(context, 2, 0) == 0);
  packet = NULL;
  assert(nestegg_read_packet(context, &packet) == 1);
  assert(nestegg_packet_track(packet, &track) == 0);
  assert(track == 2);
  nestegg_free_packet(packet);

  nestegg_destroy(context);
  buffer_destroy(&file);
}

int
main(void)
{
  test_track_limit();
  test_invalid_track_numbers();
  test_indexed_access();
  return EXIT_SUCCESS;
}
