/*
 * Copyright © 2014 Mozilla Foundation
 *
 * This program is made available under an ISC-style license.  See the
 * accompanying file LICENSE for details.
 */
#include <assert.h>
#include <math.h>
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
static int seek_fail_count = 0;

static size_t read_max = 0; /* 0 = unlimited */
static int64_t read_max_offset_seen = 0;

static int64_t
stdio_read(void * p, size_t length, void * file)
{
  size_t r;
  FILE * fp = file;

  int64_t start_offset = ftell(fp);
  int64_t end_offset = start_offset + length;

  assert(fake_eos == -1 || start_offset <= fake_eos);
  if (fake_eos != -1 && end_offset > fake_eos) {
    if (start_offset >= fake_eos)
      return 0;
    length = fake_eos - start_offset;
  }

  if (read_max > 0 && length > read_max)
    length = read_max;

  r = fread(p, 1, length, fp);
  if (r == 0 && feof(fp))
    return 0;
  if (r == 0)
    return -1;

  {
    int64_t pos = ftell(fp);
    if (pos > read_max_offset_seen)
      read_max_offset_seen = pos;
  }
  return r;
}

static int
stdio_seek(int64_t offset, int whence, void * file)
{
  FILE * fp = file;
  long off = offset;
  assert(off == offset);
  /* Because the fake_eos stuff is lazy calculating offsets. */
  assert(whence == SEEK_SET);
  if (seek_fail_count > 0) {
    seek_fail_count -= 1;
    return -1;
  }
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
test(char const * path, int64_t read_limit, int resume, int fuzz)
{
  FILE * fp;
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

  nestegg_io io;
  memset(&io, 0, sizeof(io));
  io.read = stdio_read;
  io.seek = stdio_seek;
  io.tell = stdio_tell;

  fp = fopen(path, "rb");
  if (!fp)
    return EXIT_FAILURE;

  if (read_limit == 0) {
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
  read_max_offset_seen = 0;
  r = nestegg_init(&ctx, io, NULL, read_limit);
  if (r != 0)
    return EXIT_FAILURE;

  /* When max_offset is set, verify the I/O callback was never invoked
     past that offset. */
  if (read_limit > 0)
    assert(read_max_offset_seen <= read_limit);

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
        printf("%u %u %u %u %u %u %u %u %u %u",
               vparams.stereo_mode, vparams.width, vparams.height,
               vparams.display_width, vparams.display_height,
               vparams.crop_bottom, vparams.crop_top,
               vparams.crop_left, vparams.crop_right,
               vparams.alpha_mode);
        /* Avoid printing default values for various colourspace fields. */
        if (vparams.matrix_coefficients != 2 || vparams.range != 0 ||
            vparams.transfer_characteristics != 2 || vparams.primaries != 2) {
          printf(" %u %u %u %u",
                 vparams.matrix_coefficients, vparams.range,
                 vparams.transfer_characteristics, vparams.primaries);
        }
        if (vparams.projection_type != 0 ||
            vparams.projection_pose_yaw != 0 ||
            vparams.projection_pose_pitch != 0 ||
            vparams.projection_pose_roll != 0) {
          printf(" %u %f %f %f",
                 vparams.projection_type,
                 vparams.projection_pose_yaw,
                 vparams.projection_pose_pitch,
                 vparams.projection_pose_roll);
        }
        if (!isnan(vparams.primary_r_chromacity_x) ||
            !isnan(vparams.primary_r_chromacity_y) ||
            !isnan(vparams.primary_g_chromacity_x) ||
            !isnan(vparams.primary_g_chromacity_y) ||
            !isnan(vparams.primary_b_chromacity_x) ||
            !isnan(vparams.primary_b_chromacity_y) ||
            !isnan(vparams.white_point_chromaticity_x) ||
            !isnan(vparams.white_point_chromaticity_y) ||
            !isnan(vparams.luminance_max) ||
            !isnan(vparams.luminance_min)) {
          printf(" %f %f %f %f %f %f %f %f %f %f",
                 vparams.primary_r_chromacity_x,
                 vparams.primary_r_chromacity_y,
                 vparams.primary_g_chromacity_x,
                 vparams.primary_g_chromacity_y,
                 vparams.primary_b_chromacity_x,
                 vparams.primary_b_chromacity_y,
                 vparams.white_point_chromaticity_x,
                 vparams.white_point_chromaticity_y,
                 vparams.luminance_max,
                 vparams.luminance_min);
        }
        if (vparams.max_cll != 0 || vparams.max_fall != 0) {
          printf(" %u %u", vparams.max_cll, vparams.max_fall);
        }
        printf("\n");
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
        printf("unknown track type\n");
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
    {
      int64_t pkt_end_offset;
      nestegg_packet_end_offset(pkt, &pkt_end_offset);
      assert(pkt_end_offset > 0);
    }
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

  /* Test seek-then-read: seek to the middle of the stream using cues,
     then verify we can still read packets. */
  if (duration != (uint64_t) ~0 && cues) {
    r = nestegg_track_seek(ctx, 0, duration / 2);
    if (r == 0) {
      pkt = NULL;
      r = nestegg_read_packet(ctx, &pkt);
      if (r == 1 && pkt) {
        nestegg_packet_tstamp(pkt, &pkt_tstamp);
        if (!fuzz)
          printf("seek %llu\n", (unsigned long long) pkt_tstamp);
        nestegg_free_packet(pkt);
      }
    }
  }

  nestegg_destroy(ctx);
  fclose(fp);
  return EXIT_SUCCESS;
}

static void
test_read_reset_seek_failure(char const * path, int64_t read_limit)
{
  FILE * fp;
  nestegg * ctx;
  nestegg_packet * last_pkt;
  nestegg_packet * pkt;
  uint64_t total_frames;
  nestegg_io io;
  uint64_t duration = ~0;
  int cues, r;
  int64_t saved_fake_eos = fake_eos;
  int saved_seek_fail_count = seek_fail_count;

  memset(&io, 0, sizeof(io));
  io.read = stdio_read;
  io.seek = stdio_seek;
  io.tell = stdio_tell;

  fp = fopen(path, "rb");
  assert(fp);

  if (read_limit == 0) {
    fseek(fp, 0, SEEK_END);
    read_limit = ftell(fp);
    fseek(fp, 0, SEEK_SET);
  }

  io.userdata = fp;

  fake_eos = -1;
  seek_fail_count = 0;

  ctx = NULL;
  r = nestegg_init(&ctx, io, NULL, read_limit);
  assert(r == 0);

  nestegg_duration(ctx, &duration);
  cues = nestegg_has_cues(ctx);

  if (duration != (uint64_t) ~0 && cues) {
    r = nestegg_track_seek(ctx, 0, duration / 2);
    assert(r == 0);

    /* Block the next packet read at the current raw stream position so the
       subsequent read_reset must seek back to recover. */
    fake_eos = ftell(fp);
    pkt = NULL;
    r = nestegg_read_packet(ctx, &pkt);
    assert(r <= 0);
    assert(pkt == NULL);

    seek_fail_count = 1;
    r = nestegg_read_reset(ctx);
    assert(r == -1);

    last_pkt = NULL;
    r = nestegg_read_last_packet(ctx, 0, &last_pkt);
    assert(r == -1);
    assert(last_pkt == NULL);

    total_frames = 0;
    r = nestegg_read_total_frames_count(ctx, &total_frames);
    assert(r == -1);

    fake_eos = -1;
    r = nestegg_read_reset(ctx);
    assert(r == 0);

    pkt = NULL;
    r = nestegg_read_packet(ctx, &pkt);
    assert(r == 1);
    assert(pkt != NULL);
    nestegg_free_packet(pkt);

    /* Force restore failure inside helper scans too, not just read_reset. */
    r = nestegg_track_seek(ctx, 0, duration / 2);
    assert(r == 0);

    fake_eos = ftell(fp);
    seek_fail_count = 1;
    last_pkt = NULL;
    r = nestegg_read_last_packet(ctx, 0, &last_pkt);
    assert(r == -1);
    assert(last_pkt == NULL);

    fake_eos = -1;
    seek_fail_count = 0;
    r = nestegg_track_seek(ctx, 0, duration / 2);
    assert(r == 0);
    pkt = NULL;
    r = nestegg_read_packet(ctx, &pkt);
    assert(r == 1);
    assert(pkt != NULL);
    nestegg_free_packet(pkt);

    r = nestegg_track_seek(ctx, 0, duration / 2);
    assert(r == 0);

    fake_eos = ftell(fp);
    seek_fail_count = 1;
    total_frames = 0;
    r = nestegg_read_total_frames_count(ctx, &total_frames);
    assert(r == -1);

    fake_eos = -1;
    seek_fail_count = 0;
    r = nestegg_track_seek(ctx, 0, duration / 2);
    assert(r == 0);
    pkt = NULL;
    r = nestegg_read_packet(ctx, &pkt);
    assert(r == 1);
    assert(pkt != NULL);
    nestegg_free_packet(pkt);
  }

  nestegg_destroy(ctx);
  fclose(fp);

  fake_eos = saved_fake_eos;
  seek_fail_count = saved_seek_fail_count;
}

int
main(int argc, char * argv[])
{
  int resume = 0, fuzz = 0, seek_fail_regress = 0;
  int64_t read_limit = -1;
  int i;

  if (argc < 2)
    return EXIT_FAILURE;

  for (i = 2; i < argc; i++) {
    if (argv[i][0] != '-')
      return EXIT_FAILURE;
    switch (argv[i][1]) {
    case 'l':
      /* -l: use file size as max_offset. */
      read_limit = 0; /* sentinel; resolved after fopen. */
      break;
    case 'o':
      /* -o <N>: explicit max_offset. */
      if (++i >= argc)
        return EXIT_FAILURE;
      read_limit = strtol(argv[i], NULL, 10);
      break;
    case 'r':
      resume = 1;
      break;
    case 'z':
      fuzz = 1;
      break;
    case 's':
      read_max = 16;
      break;
    case 'R':
      seek_fail_regress = 1;
      break;
    default:
      return EXIT_FAILURE;
    }
  }

  if (seek_fail_regress)
    test_read_reset_seek_failure(argv[1], read_limit);

  return test(argv[1], read_limit, resume, fuzz);
}
