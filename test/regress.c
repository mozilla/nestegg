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
print_hash(uint8_t const * data, size_t len)
{
  sha1nfo s;
  uint8_t const * hash;
  int i;

  sha1_init(&s);
  sha1_write(&s, (char const *) data, len);
  hash = sha1_result(&s);

  for (i = 0; i < 20; i++) {
    printf("%02x", hash[i]);
  }
  printf(" %zu", len);
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
test(char const * path, int limit, int resume, int fuzz)
{
  FILE * fp;
  int64_t read_limit = -1;
  int64_t true_eos = -1;
  int r, type, id, track_encoding, pkt_keyframe, pkt_encryption, cues;
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

  nestegg_io io = {
    stdio_read,
    stdio_seek,
    stdio_tell,
    NULL
  };

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
  nestegg_tstamp_scale(ctx, &tstamp_scale);
  cues = nestegg_has_cues(ctx);
  if (!fuzz) {
    printf("%u %llu %llu %d\n", tracks, (unsigned long long) duration,
           (unsigned long long) tstamp_scale, cues);
  }

  for (i = 0; i < tracks; ++i) {
    type = nestegg_track_type(ctx, i);
    id = nestegg_track_codec_id(ctx, i);
    nestegg_track_codec_data_count(ctx, i, &data_items);
    track_encoding = nestegg_track_encoding(ctx, i);
    r = nestegg_track_default_duration(ctx, i, &default_duration);
    if (!fuzz) {
      printf("%d %d %u %u", type, id, data_items, track_encoding);
      if (r == 0)
        printf(" %llu", default_duration);
    }
    if (track_encoding == NESTEGG_ENCODING_ENCRYPTION) {
      nestegg_track_content_enc_key_id(ctx, i, &track_content_enc_key_id, &length);
      if (!fuzz) {
        printf(" ");
        print_hash(track_content_enc_key_id, length);
      }
    }
    if (!fuzz) {
      printf("\n");
    }
    for (j = 0; j < data_items; ++j) {
      nestegg_track_codec_data(ctx, i, j, &codec_data, &length);
      if (!fuzz) {
        print_hash(codec_data, length);
        printf("\n");
      }
    }
    switch (type) {
    case NESTEGG_TRACK_VIDEO:
      nestegg_track_video_params(ctx, i, &vparams);
      if (!fuzz) {
        printf("%u %u %u %u %u %u %u %u %u %u\n",
               vparams.stereo_mode, vparams.width, vparams.height,
               vparams.display_width, vparams.display_height,
               vparams.crop_bottom, vparams.crop_top,
               vparams.crop_left, vparams.crop_right,
               vparams.alpha_mode);
      }
      break;
    case NESTEGG_TRACK_AUDIO:
      nestegg_track_audio_params(ctx, i, &aparams);
      if (!fuzz) {
        printf("%f %u %u %llu %llu\n",
               aparams.rate, aparams.channels, aparams.depth,
               (unsigned long long) aparams.codec_delay,
               (unsigned long long) aparams.seek_preroll);
      }
      break;
    case NESTEGG_TRACK_UNKNOWN:
      if (!fuzz) {
        printf("unknown track\n");
      }
      break;
    default:
      if (!fuzz) {
        printf("unexpected track type\n");
        abort();
      }
    }
  }

  if (resume) {
    fake_eos = ftell(fp);
  }

  for (;;) {
    pkt = NULL;
    r = nestegg_read_packet(ctx, &pkt);
    if (r == 0 && resume && fake_eos < true_eos) {
      assert(pkt == NULL);
      assert(fake_eos != -1 && true_eos != -1);
      fake_eos += 1;
      r = nestegg_read_reset(ctx);
      assert(r == 0);
      continue;
    } else if (r <= 0) {
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

    if (!fuzz) {
      printf("%u %d %llu %u %d", pkt_track, pkt_keyframe, (unsigned long long) pkt_tstamp, pkt_cnt,
             pkt_encryption);
      if (pkt_duration != 0)
        printf(" %llu", (unsigned long long) pkt_duration);
      if (pkt_discard_padding != 0)
        printf(" %lld", (long long) pkt_discard_padding);
      if (pkt_reference_block != 0)
        printf(" %lld", (long long) pkt_reference_block);
      if (pkt_additional) {
        printf(" ");
        print_hash(pkt_additional, length);
      }
    }
    if (pkt_encryption == NESTEGG_PACKET_HAS_SIGNAL_BYTE_ENCRYPTED ||
        pkt_encryption == NESTEGG_PACKET_HAS_SIGNAL_BYTE_PARTITIONED) {
      nestegg_packet_iv(pkt, &pkt_encryption_iv, &length);
      if (!fuzz) {
        printf(" ");
        print_hash(pkt_encryption_iv, length);
      }
    }

    if (pkt_encryption == NESTEGG_PACKET_HAS_SIGNAL_BYTE_PARTITIONED) {
      nestegg_packet_offsets(pkt, &pkt_partition_offsets, &pkt_num_offsets);

      if (!fuzz) {
        for (i = 0; i < pkt_num_offsets; ++i) {
          printf(" %u", pkt_partition_offsets[i]);
        }

        printf(" %u", (unsigned int) pkt_num_offsets);
      }
    }

    for (i = 0; i < pkt_cnt; ++i) {
      nestegg_packet_data(pkt, i, &ptr, &length);
      if (!fuzz) {
        printf(" ");
        print_hash(ptr, length);
      }
    }
    if (!fuzz) {
      printf("\n");
    }

    nestegg_free_packet(pkt);
  }

  /* We don't know how many Clusters there are, so just check a handful. */
  for (i = 0; i < 10; ++i) {
    int64_t start = -1, end = -1;
    uint64_t tstamp = ~0;
    nestegg_get_cue_point(ctx, i, read_limit, &start, &end, &tstamp);
    if (start == -1 && i == 0)
      break;
    if (!fuzz) {
      printf("%d %lld %lld %llu\n", i, start, end, tstamp);
    }
    if (end == -1)
      break;
  }

  nestegg_destroy(ctx);
  fclose(fp);
  return EXIT_SUCCESS;
}

int
main(int argc, char * argv[])
{
  int limit, resume, fuzz;

  if (argc != 2 && argc != 3)
    return EXIT_FAILURE;

  limit = argc == 3 && argv[2][0] == '-' && argv[2][1] == 'l';
  resume = argc == 3 && argv[2][0] == '-' && argv[2][1] == 'r';
  fuzz = argc == 3 && argv[2][0] == '-' && argv[2][1] == 'z';

  return test(argv[1], limit, resume, fuzz);
}
