/*
 * Copyright © 2014 Mozilla Foundation
 *
 * This program is made available under an ISC-style license.  See the
 * accompanying file LICENSE for details.
 */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "nestegg/nestegg.h"

#include "sha1.c"

static void
print_hash(uint8_t const * hash)
{
  int i;

  for (i = 0; i < 20; i++) {
    printf("%02x", hash[i]);
  }
}

static int64_t fake_eos = -1;

static int
stdio_read(void * p, size_t length, void * file)
{
  size_t r;
  FILE * fp = file;

  int64_t start_offset = ftell(fp);
  int64_t end_offset = start_offset + length;

  assert(fake_eos == -1 || start_offset <= fake_eos);
  if (fake_eos != -1 && end_offset > fake_eos) {
    return 0;
  }

  r = fread(p, length, 1, fp);
  if (r == 0 && feof(fp))
    return 0;
  return r == 0 ? -1 : 1;
}

static int
stdio_seek(int64_t offset, int whence, void * file)
{
  FILE * fp = file;
  long off = offset;
  assert(off == offset);
  /* Because the fake_eos stuff is lazy calculating offsets. */
  assert(whence == SEEK_SET);
  if (fake_eos != -1 && offset > fake_eos) {
    return -1;
  }
  return fseek(fp, off, whence);
}

static int64_t
stdio_tell(void * fp)
{
  int64_t offset = ftell(fp);
  assert(fake_eos == -1 || offset <= fake_eos);
  return offset;
}

int
test(char const * path, int limit, int resume)
{
  FILE * fp;
  int64_t read_limit = -1;
  int64_t true_eos = -1;
  int r, type, id, pkt_keyframe, pkt_encryption;
  nestegg * ctx;
  nestegg_audio_params aparams;
  nestegg_packet * pkt;
  nestegg_video_params vparams;
  nestegg_encryption_params encryption_params;
  size_t length, size, pkt_additional_length, pkt_encryption_iv_length;
  uint64_t duration = ~0, pkt_tstamp, pkt_duration;
  int64_t pkt_discard_padding, pkt_reference_block;
  unsigned char * codec_data, * ptr, * pkt_additional, * pkt_encryption_iv;
  unsigned int i, j, tracks = 0, pkt_cnt, pkt_track;
  unsigned int data_items = 0;
  nestegg_io io = {
    stdio_read,
    stdio_seek,
    stdio_tell,
    NULL
  };
  sha1nfo s;

  fp = fopen(path, "rb");
  if (!fp)
    return EXIT_FAILURE;

  if (limit) {
    fseek(fp, 0, SEEK_END);
    read_limit = ftell(fp);
    fseek(fp, 0, SEEK_SET);
  }

  if (resume) {
    fseek(fp, 0, SEEK_END);
    true_eos = ftell(fp);
    fseek(fp, 0, SEEK_SET);
  }

  io.userdata = fp;

  ctx = NULL;
  r = nestegg_init(&ctx, io, NULL, read_limit);
  if (r != 0)
    return EXIT_FAILURE;

  nestegg_track_count(ctx, &tracks);
  nestegg_duration(ctx, &duration);
  printf("%u %llu\n", tracks, (unsigned long long) duration);

  for (i = 0; i < tracks; ++i) {
    type = nestegg_track_type(ctx, i);
    id = nestegg_track_codec_id(ctx, i);
    nestegg_track_codec_data_count(ctx, i, &data_items);
    nestegg_track_encryption(ctx, i, &encryption_params);
    printf("%d %d %u %u\n", type, id, data_items, encryption_params.content_encoding_type);
    for (j = 0; j < data_items; ++j) {
      nestegg_track_codec_data(ctx, i, j, &codec_data, &length);
      sha1_init(&s);
      sha1_write(&s, (char const *) codec_data, length);
      print_hash(sha1_result(&s));
      printf(" %u\n", (unsigned int) length);
    }
    switch (type) {
    case NESTEGG_TRACK_VIDEO:
      nestegg_track_video_params(ctx, i, &vparams);
      printf("%u %u %u %u %u %u %u %u %u %u\n",
             vparams.stereo_mode, vparams.width, vparams.height,
             vparams.display_width, vparams.display_height,
             vparams.crop_bottom, vparams.crop_top,
             vparams.crop_left, vparams.crop_right,
             vparams.alpha_mode);
      break;
    case NESTEGG_TRACK_AUDIO:
      nestegg_track_audio_params(ctx, i, &aparams);
      printf("%f %u %u %llu %llu\n",
             aparams.rate, aparams.channels, aparams.depth,
             (unsigned long long) aparams.codec_delay,
             (unsigned long long) aparams.seek_preroll);
      break;
    case NESTEGG_TRACK_UNKNOWN:
      printf("unknown track\n");
      break;
    default:
      abort();
    }
  }

  if (resume) {
    fake_eos = ftell(fp);
  }

  for (;;) {
    r = nestegg_read_packet(ctx, &pkt);
    if (r == 0 && resume && fake_eos < true_eos) {
      assert(fake_eos != -1 && true_eos != -1);
      fake_eos += 1;
      r = nestegg_read_reset(ctx);
      assert(r == 0);
      continue;
    } else if (r <= 0) {
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
    nestegg_packet_additional_data(pkt, 1, &pkt_additional, &pkt_additional_length);
    pkt_encryption = nestegg_packet_encryption(pkt, &pkt_encryption_iv, &pkt_encryption_iv_length);

    printf("%u %d %llu %u %d", pkt_track, pkt_keyframe, (unsigned long long) pkt_tstamp, pkt_cnt,
            pkt_encryption);
    if (pkt_duration != 0)
      printf(" %llu", (unsigned long long) pkt_duration);
    if (pkt_discard_padding != 0)
      printf(" %lld", (long long) pkt_discard_padding);
    if (pkt_reference_block != 0)
      printf(" %lld", (long long) pkt_reference_block);
    if (pkt_additional) {
      sha1_init(&s);
      sha1_write(&s, (char const *) pkt_additional, pkt_additional_length);
      printf(" ");
      print_hash(sha1_result(&s));
      printf(" %u", (unsigned int) pkt_additional_length);
    }
    if (pkt_encryption == 1) {
      sha1_init(&s);
      sha1_write(&s, (char const *) pkt_encryption_iv, pkt_encryption_iv_length);
      printf(" ");
      print_hash(sha1_result(&s));
      printf(" %u", (unsigned int) pkt_encryption_iv_length);
    }

    for (i = 0; i < pkt_cnt; ++i) {
      nestegg_packet_data(pkt, i, &ptr, &size);
      sha1_init(&s);
      sha1_write(&s, (char const *) ptr, size);
      printf(" ");
      print_hash(sha1_result(&s));
      printf(" %u", (unsigned int) size);
    }
    printf("\n");

    nestegg_free_packet(pkt);
  }

  nestegg_destroy(ctx);
  fclose(fp);
  return EXIT_SUCCESS;
}

int
main(int argc, char * argv[])
{
  int limit, resume;

  if (argc != 2 && argc != 3)
    return EXIT_FAILURE;

  limit = argc == 3 && argv[2][0] == '-' && argv[2][1] == 'l';
  resume = argc == 3 && argv[2][0] == '-' && argv[2][1] == 'r';

  return test(argv[1], limit, resume);
}
