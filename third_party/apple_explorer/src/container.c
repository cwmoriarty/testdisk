#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "aex_internal.h"
#include <ctype.h>
#include <sys/stat.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <direct.h>
#else
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/disk.h>
#endif
#ifdef __linux__
#include <linux/fs.h>
#endif
#endif

/* ---------------- Cross-Platform Raw File / Device Handle ---------------- */

typedef struct {
#ifdef _WIN32
    HANDLE   hfile;
#else
    int      fd;
#endif
    uint32_t align;
    uint64_t size;
} os_file_t;

static int os_is_directory(const char *path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0);
#else
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
#endif
}

static int os_mkdir_one(const char *path) {
#ifdef _WIN32
    if (_mkdir(path) == 0 || errno == EEXIST) return 0;
    return -errno;
#else
    if (mkdir(path, 0755) == 0 || errno == EEXIST) return 0;
    return -errno;
#endif
}

static int os_open_ro(const char *path, os_file_t *out) {
    memset(out, 0, sizeof(*out));
#ifdef _WIN32
    HANDLE h = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (h == INVALID_HANDLE_VALUE) return -ENOENT;
    out->hfile = h;
    out->align = 1U;

    LARGE_INTEGER fsz;
    if (GetFileSizeEx(h, &fsz) && fsz.QuadPart > 0) {
        out->size = (uint64_t)fsz.QuadPart;
    } else {
        GET_LENGTH_INFORMATION li;
        DWORD br = 0;
        if (DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &li, sizeof(li), &br, NULL)) {
            out->size = (uint64_t)li.Length.QuadPart;
            out->align = 4096U;
        }
    }
    return 0;
#else
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -errno;
    out->fd = fd;
    out->align = 1U;
    struct stat st;
    if (fstat(fd, &st) == 0) {
        if (S_ISREG(st.st_mode)) {
            out->size = (uint64_t)st.st_size;
        } else {
            out->align = 4096U;
#ifdef __APPLE__
            uint32_t bsz = 0;
            uint64_t bcnt = 0;
            if (ioctl(fd, DKIOCGETBLOCKSIZE, &bsz) == 0 && bsz >= 512U &&
                ioctl(fd, DKIOCGETBLOCKCOUNT, &bcnt) == 0) {
                out->size = bcnt * (uint64_t)bsz;
            }
#endif
#ifdef __linux__
            uint64_t bytes = 0;
            if (ioctl(fd, BLKGETSIZE64, &bytes) == 0) out->size = bytes;
#endif
            if (out->size == 0) {
                off_t end = lseek(fd, 0, SEEK_END);
                if (end > 0) out->size = (uint64_t)end;
            }
        }
    }
    return 0;
#endif
}

static void os_close(os_file_t *f) {
#ifdef _WIN32
    if (f->hfile && f->hfile != INVALID_HANDLE_VALUE) {
        CloseHandle(f->hfile);
        f->hfile = INVALID_HANDLE_VALUE;
    }
#else
    if (f->fd >= 0) {
        close(f->fd);
        f->fd = -1;
    }
#endif
}

static int os_pread_raw(os_file_t *f, uint64_t off, size_t len, void *buf, size_t *out_got) {
    if (len == 0) { *out_got = 0; return 0; }
#ifdef _WIN32
    uint8_t *dst = (uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        OVERLAPPED ov;
        memset(&ov, 0, sizeof(ov));
        uint64_t cur = off + done;
        ov.Offset = (DWORD)(cur & 0xFFFFFFFFULL);
        ov.OffsetHigh = (DWORD)(cur >> 32);
        DWORD chunk = (len - done > (1U << 20)) ? (1U << 20) : (DWORD)(len - done);
        DWORD got = 0;
        if (!ReadFile(f->hfile, dst + done, chunk, &got, &ov) || got == 0) break;
        done += (size_t)got;
    }
    *out_got = done;
    return 0;
#else
    uint8_t *dst = (uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t r = pread(f->fd, dst + done, len - done, (off_t)(off + done));
        if (r <= 0) break;
        done += (size_t)r;
    }
    *out_got = done;
    return 0;
#endif
}

static int os_pread_aligned(os_file_t *f, uint64_t off, size_t len, void *buf) {
    if (len == 0) return 0;
    if (f->align <= 1U || ((off % f->align) == 0 && (len % f->align) == 0)) {
        size_t got = 0;
        int rc = os_pread_raw(f, off, len, buf, &got);
        if (rc != 0 || got != len) return -EIO;
        return 0;
    }
    uint64_t a_start = (off / f->align) * f->align;
    uint64_t a_end = ((off + len + f->align - 1ULL) / f->align) * f->align;
    size_t a_len = (size_t)(a_end - a_start);
    uint8_t *tmp = (uint8_t *)malloc(a_len);
    if (!tmp) return -ENOMEM;
    size_t got = 0;
    int rc = os_pread_raw(f, a_start, a_len, tmp, &got);
    if (rc != 0 || got < (size_t)(off - a_start) + len) {
        free(tmp);
        return -EIO;
    }
    memcpy(buf, tmp + (size_t)(off - a_start), len);
    free(tmp);
    return 0;
}

/* ---------------- Container Definitions (.sparsebundle, .sparseimage, UDIF .dmg) ---------------- */

typedef struct {
    uint32_t type;
    uint64_t virt_off;
    uint64_t virt_len;
    uint64_t comp_off;
    uint64_t comp_len;
} udif_run_t;

struct aex_stream {
    aex_container_kind_t kind;
    uint64_t             virtual_size;
    uint32_t             band_size;
    int                  encrypted;

    /* Callback IO mode */
    aex_read_fn          cb_read;
    void                *cb_ctx;

    /* OS file mode (raw / .dmg / .sparseimage) */
    os_file_t            file;
    int                  has_file;

    /* .sparsebundle / .backupbundle */
    char                *bundle_dir;
    uint64_t             enc_data_offset;
    uint32_t             enc_chunk_size;
    size_t               enc_aes_key_len;
    uint8_t              enc_aes_key[32];
    uint8_t              enc_hmac_key[20];

    /* .sparseimage */
    uint32_t            *sprs_map;
    uint32_t             sprs_band_count;
    uint64_t             sprs_data_start;

    /* UDIF .dmg */
    udif_run_t          *dmg_runs;
    size_t               dmg_run_count;
    uint64_t             dmg_cache_off;
    uint64_t             dmg_cache_len;
    uint8_t             *dmg_cache_buf;
};

/* Base64 decoder for UDIF XML blkx plist */
static int b64_decode_buf(const char *in, size_t in_len, uint8_t **out_buf, size_t *out_len) {
    size_t cap = (in_len / 4U + 2U) * 3U;
    uint8_t *dst = (uint8_t *)malloc(cap ? cap : 1U);
    if (!dst) return -ENOMEM;
    size_t pos = 0;
    uint32_t val = 0;
    int bits = -8;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        int d = -1;
        if (c >= 'A' && c <= 'Z') d = c - 'A';
        else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
        else if (c >= '0' && c <= '9') d = c - '0' + 52;
        else if (c == '+') d = 62;
        else if (c == '/') d = 63;
        else if (c == '=') break;
        else continue;
        val = (val << 6) | (uint32_t)d;
        bits += 6;
        if (bits >= 0) {
            dst[pos++] = (uint8_t)((val >> bits) & 0xFFU);
            bits -= 8;
        }
    }
    *out_buf = dst;
    *out_len = pos;
    return 0;
}

/* Parse integer key in Apple XML plist (<key>name</key>...<integer>1234</integer>) */
static int plist_get_u64(const char *xml, const char *key_name, uint64_t *out_val) {
    char pat[128];
    snprintf(pat, sizeof(pat), "<key>%s</key>", key_name);
    const char *hit = strstr(xml, pat);
    if (!hit) return -ENOENT;
    const char *itag = strstr(hit + strlen(pat), "<integer>");
    if (!itag) return -ENOENT;
    itag += strlen("<integer>");
    while (*itag && isspace((unsigned char)*itag)) itag++;
    if (strncmp(itag, "0x", 2) == 0 || strncmp(itag, "0X", 2) == 0) {
        *out_val = strtoull(itag + 2, NULL, 16);
    } else {
        *out_val = strtoull(itag, NULL, 10);
    }
    return 0;
}

/* Unwrap Apple Disk Image v2 Encrypted Header ('encrcdsa') if present */
static int try_unwrap_encrcdsa(
    const uint8_t *hdr,
    size_t hdr_len,
    const char *password,
    aex_stream_t *st
) {
    if (hdr_len < 128U || memcmp(hdr, "encrcdsa", 8) != 0) return -EINVAL;
    st->encrypted = 1;
    if (!password || !password[0]) return -EACCES;

    /* v2 header layout (big-endian):
       0..7: "encrcdsa"
       8..11: version (2)
       12..15: enc_iv_size (16)
       24..27: key_bits (128 or 256)
       36..39: blocksize (chunk size, typically 4096)
       40..47: datasize (virtual encrypted payload bytes)
       48..55: dataoffset (byte offset where encrypted chunks begin)
       followed by keyblobs; search for kdf_salt_len=20 + kdf_iters + wrapped AES+HMAC keys */
    uint32_t key_bits = aex_be32(hdr + 24U);
    uint32_t chunk_sz = aex_be32(hdr + 36U);
    uint64_t data_sz = aex_be64(hdr + 40U);
    uint64_t data_off = aex_be64(hdr + 48U);
    if ((key_bits != 128U && key_bits != 256U) || chunk_sz < 512U || (chunk_sz % 16U) != 0) {
        return -ENOTSUP;
    }

    size_t aes_klen = key_bits / 8U;
    /* Scan header keyblobs for PBKDF2-HMAC-SHA1 parameter block (kdf_algorithm == 103 == 0x00000067) */
    for (size_t off = 56U; off + 96U <= hdr_len; off += 4U) {
        if (aex_be32(hdr + off) == 103U && aex_be32(hdr + off + 12U) == 20U) {
            uint32_t iters = aex_be32(hdr + off + 8U);
            const uint8_t *salt = hdr + off + 16U;
            uint32_t blob_iv_len = aex_be32(hdr + off + 36U);
            const uint8_t *blob_iv = hdr + off + 40U;
            uint32_t wrapped_len = aex_be32(hdr + off + 72U);
            const uint8_t *wrapped = hdr + off + 76U;
            if (iters == 0 || iters > 5000000U || off + 76U + wrapped_len > hdr_len) continue;
            (void)blob_iv_len;
            (void)blob_iv;

            uint8_t dk[32];
            aex_pbkdf2_sha1(password, strlen(password), salt, 20U, iters, dk, aes_klen);
            uint8_t plain[128];
            if (wrapped_len <= sizeof(plain) &&
                aex_aes_key_unwrap(dk, aes_klen, wrapped, wrapped_len, plain) == 0) {
                memcpy(st->enc_aes_key, plain, aes_klen);
                memcpy(st->enc_hmac_key, plain + aes_klen, 20U);
                st->enc_aes_key_len = aes_klen;
                st->enc_chunk_size = chunk_sz;
                st->enc_data_offset = data_off;
                if (data_sz > 0) st->virtual_size = data_sz;
                return 0;
            }
        }
    }
    return -EACCES;
}

static int open_sparsebundle_dir(const char *dir_path, const char *password, aex_stream_t **out_stream) {
    char plist_path[1024];
    snprintf(plist_path, sizeof(plist_path), "%s/Info.plist", dir_path);
    os_file_t pf;
    if (os_open_ro(plist_path, &pf) != 0) {
        snprintf(plist_path, sizeof(plist_path), "%s/Info.bckup", dir_path);
        if (os_open_ro(plist_path, &pf) != 0) return -ENOENT;
    }
    if (pf.size == 0 || pf.size > (1ULL << 20)) {
        os_close(&pf);
        return -EINVAL;
    }
    char *xml = (char *)calloc(1, (size_t)pf.size + 1U);
    if (!xml) { os_close(&pf); return -ENOMEM; }
    size_t got = 0;
    (void)os_pread_raw(&pf, 0, (size_t)pf.size, xml, &got);
    os_close(&pf);

    uint64_t band_sz = 0, total_sz = 0;
    if (plist_get_u64(xml, "band-size", &band_sz) != 0 ||
        plist_get_u64(xml, "size", &total_sz) != 0 ||
        band_sz < 4096ULL || total_sz == 0) {
        free(xml);
        return -EINVAL;
    }
    free(xml);

    aex_stream_t *st = (aex_stream_t *)calloc(1, sizeof(aex_stream_t));
    if (!st) return -ENOMEM;
    st->kind = AEX_CONTAINER_SPARSEBUNDLE;
    st->band_size = (uint32_t)band_sz;
    st->virtual_size = total_sz;
    st->bundle_dir = strdup(dir_path);

    /* Check token or band 0 for encrcdsa encrypted bundle header */
    const char *hdr_candidates[2] = { "token", "bands/0" };
    for (int c = 0; c < 2; c++) {
        char hp[1024];
        snprintf(hp, sizeof(hp), "%s/%s", dir_path, hdr_candidates[c]);
        os_file_t tf;
        if (os_open_ro(hp, &tf) == 0) {
            uint8_t hbuf[4096];
            size_t hgot = 0;
            (void)os_pread_raw(&tf, 0, sizeof(hbuf), hbuf, &hgot);
            os_close(&tf);
            if (hgot >= 128U && memcmp(hbuf, "encrcdsa", 8) == 0) {
                int rc = try_unwrap_encrcdsa(hbuf, hgot, password, st);
                if (rc != 0) {
                    free(st->bundle_dir);
                    free(st);
                    return rc;
                }
                break;
            }
        }
    }

    *out_stream = st;
    return 0;
}

static int try_open_sparseimage(os_file_t *f, aex_stream_t **out_stream) {
    uint8_t hdr[4096];
    if (f->size < 4096ULL) return -EINVAL;
    if (os_pread_aligned(f, 0, sizeof(hdr), hdr) != 0) return -EIO;
    if (memcmp(hdr, "sprs", 4) != 0) return -EINVAL;

    uint32_t sec_per_band = aex_be32(hdr + 4U);
    uint64_t total_sec = aex_be64(hdr + 28U);
    if (total_sec == 0) total_sec = (uint64_t)aex_be32(hdr + 8U);
    if (sec_per_band == 0 || total_sec == 0) return -EINVAL;

    uint64_t band_bytes = (uint64_t)sec_per_band * 512ULL;
    uint64_t total_bytes = total_sec * 512ULL;
    uint64_t nbands = (total_bytes + band_bytes - 1ULL) / band_bytes;
    if (nbands > 1000000ULL) return -ENOMEM;

    uint32_t *map = (uint32_t *)calloc((size_t)nbands, sizeof(uint32_t));
    if (!map) return -ENOMEM;

    /* First 1008 entries sit at offset 64..4095 of header; zero means unallocated */
    size_t in_hdr = (nbands < 1008ULL) ? (size_t)nbands : 1008U;
    for (size_t i = 0; i < in_hdr; i++) {
        uint32_t phys_1based = aex_be32(hdr + 64U + i * 4U);
        if (phys_1based > 0) map[phys_1based - 1U] = (uint32_t)(i + 1U);
    }
    /* Wait: in Apple sprs header, hdr[64 + phys_idx*4] stores (virtual_band_index + 1)!
       So invert it: vband_to_phys[vband] = phys_idx + 1 (1-based). */
    uint32_t *v2p = (uint32_t *)calloc((size_t)nbands, sizeof(uint32_t));
    if (!v2p) { free(map); return -ENOMEM; }
    for (size_t phys_idx = 0; phys_idx < 1008U; phys_idx++) {
        uint32_t v1 = aex_be32(hdr + 64U + phys_idx * 4U);
        if (v1 >= 1U && v1 <= nbands) {
            v2p[v1 - 1U] = (uint32_t)(phys_idx + 1U);
        }
    }
    free(map);

    aex_stream_t *st = (aex_stream_t *)calloc(1, sizeof(aex_stream_t));
    if (!st) { free(v2p); return -ENOMEM; }
    st->kind = AEX_CONTAINER_SPARSEIMAGE;
    st->file = *f;
    st->has_file = 1;
    st->band_size = (uint32_t)band_bytes;
    st->virtual_size = total_bytes;
    st->sprs_map = v2p;
    st->sprs_band_count = (uint32_t)nbands;
    st->sprs_data_start = 4096ULL;
    *out_stream = st;
    return 0;
}

static int try_open_udif_dmg(os_file_t *f, aex_stream_t **out_stream) {
    if (f->size < 512ULL) return -EINVAL;
    uint8_t koly[512];
    if (os_pread_aligned(f, f->size - 512ULL, 512U, koly) != 0) return -EINVAL;
    if (memcmp(koly, "koly", 4) != 0) return -EINVAL;

    uint64_t xml_off = aex_be64(koly + 216U);
    uint64_t xml_len = aex_be64(koly + 224U);
    uint64_t total_sectors = aex_be64(koly + 492U);
    if (xml_len == 0 || xml_len > (16ULL << 20) || xml_off + xml_len > f->size) return -EINVAL;

    char *xml = (char *)calloc(1, (size_t)xml_len + 1U);
    if (!xml) return -ENOMEM;
    if (os_pread_aligned(f, xml_off, (size_t)xml_len, xml) != 0) {
        free(xml);
        return -EIO;
    }

    const char *blkx = strstr(xml, "<key>blkx</key>");
    if (!blkx) { free(xml); return -EINVAL; }

    size_t runs_cap = 256U, runs_cnt = 0;
    udif_run_t *runs = (udif_run_t *)calloc(runs_cap, sizeof(udif_run_t));
    if (!runs) { free(xml); return -ENOMEM; }

    uint64_t max_virt_end = total_sectors * 512ULL;
    const char *p = blkx;
    while ((p = strstr(p, "<data>")) != NULL) {
        p += 6;
        const char *end = strstr(p, "</data>");
        if (!end) break;
        uint8_t *mish = NULL;
        size_t mish_len = 0;
        if (b64_decode_buf(p, (size_t)(end - p), &mish, &mish_len) == 0 && mish) {
            if (mish_len >= 204U && aex_be32(mish) == 0x6D697368U) { /* 'mish' */
                uint64_t first_sec = aex_be64(mish + 8U);
                uint64_t sec_cnt = aex_be64(mish + 16U);
                uint64_t data_start = aex_be64(mish + 24U);
                uint32_t nblocks = aex_be32(mish + 200U);
                if (first_sec * 512ULL + sec_cnt * 512ULL > max_virt_end) {
                    max_virt_end = (first_sec + sec_cnt) * 512ULL;
                }
                for (uint32_t r = 0; r < nblocks; r++) {
                    size_t roff = 204U + (size_t)r * 40U;
                    if (roff + 40U > mish_len) break;
                    uint32_t etype = aex_be32(mish + roff);
                    if (etype == 0xFFFFFFFFU || etype == 0x7FFFFFFEU) continue;
                    uint64_t r_sec = aex_be64(mish + roff + 8U);
                    uint64_t r_cnt = aex_be64(mish + roff + 16U);
                    uint64_t c_off = aex_be64(mish + roff + 24U);
                    uint64_t c_len = aex_be64(mish + roff + 32U);
                    if (r_cnt == 0) continue;
                    if (runs_cnt == runs_cap) {
                        runs_cap *= 2U;
                        udif_run_t *nr = (udif_run_t *)realloc(runs, runs_cap * sizeof(udif_run_t));
                        if (!nr) break;
                        runs = nr;
                    }
                    runs[runs_cnt].type = etype;
                    runs[runs_cnt].virt_off = (first_sec + r_sec) * 512ULL;
                    runs[runs_cnt].virt_len = r_cnt * 512ULL;
                    runs[runs_cnt].comp_off = data_start + c_off;
                    runs[runs_cnt].comp_len = c_len;
                    runs_cnt++;
                }
            }
            free(mish);
        }
        p = end + 7;
    }
    free(xml);

    if (runs_cnt == 0 || max_virt_end == 0) {
        free(runs);
        return -EINVAL;
    }

    aex_stream_t *st = (aex_stream_t *)calloc(1, sizeof(aex_stream_t));
    if (!st) { free(runs); return -ENOMEM; }
    st->kind = AEX_CONTAINER_UDIF_DMG;
    st->file = *f;
    st->has_file = 1;
    st->virtual_size = max_virt_end;
    st->dmg_runs = runs;
    st->dmg_run_count = runs_cnt;
    *out_stream = st;
    return 0;
}

int aex_stream_open_path(const char *path, const char *password, aex_stream_t **out_stream) {
    if (!path || !out_stream) return -EINVAL;
    *out_stream = NULL;

    if (os_is_directory(path)) {
        return open_sparsebundle_dir(path, password, out_stream);
    }

    os_file_t f;
    int rc = os_open_ro(path, &f);
    if (rc != 0) return rc;

    if (try_open_sparseimage(&f, out_stream) == 0) return 0;
    if (try_open_udif_dmg(&f, out_stream) == 0) return 0;

    aex_stream_t *st = (aex_stream_t *)calloc(1, sizeof(aex_stream_t));
    if (!st) { os_close(&f); return -ENOMEM; }
    st->kind = AEX_CONTAINER_RAW;
    st->file = f;
    st->has_file = 1;
    st->virtual_size = f.size;

    /* Check if raw file begins with Apple Encrypted Disk Image v2 ('encrcdsa') */
    if (f.size >= 4096ULL) {
        uint8_t hdr[4096];
        if (os_pread_aligned(&f, 0, sizeof(hdr), hdr) == 0 && memcmp(hdr, "encrcdsa", 8) == 0) {
            rc = try_unwrap_encrcdsa(hdr, sizeof(hdr), password, st);
            if (rc != 0) {
                os_close(&st->file);
                free(st);
                return rc;
            }
        }
    }

    *out_stream = st;
    return 0;
}

int aex_stream_open_io(aex_read_fn read_fn, void *io_ctx, uint64_t size_bytes, aex_stream_t **out_stream) {
    if (!read_fn || !out_stream) return -EINVAL;
    aex_stream_t *st = (aex_stream_t *)calloc(1, sizeof(aex_stream_t));
    if (!st) return -ENOMEM;
    st->kind = AEX_CONTAINER_RAW;
    st->cb_read = read_fn;
    st->cb_ctx = io_ctx;
    st->virtual_size = size_bytes;
    *out_stream = st;
    return 0;
}

void aex_stream_close(aex_stream_t *st) {
    if (!st) return;
    if (st->has_file) os_close(&st->file);
    free(st->bundle_dir);
    free(st->sprs_map);
    free(st->dmg_runs);
    free(st->dmg_cache_buf);
    memset(st->enc_aes_key, 0, sizeof(st->enc_aes_key));
    memset(st->enc_hmac_key, 0, sizeof(st->enc_hmac_key));
    free(st);
}

uint64_t aex_stream_size(const aex_stream_t *stream) {
    return stream ? stream->virtual_size : 0ULL;
}

aex_container_kind_t aex_stream_kind(const aex_stream_t *stream) {
    return stream ? stream->kind : AEX_CONTAINER_RAW;
}

/* Read underlying unencrypted/backing container bytes before optional encrcdsa chunk decryption */
static int stream_read_backing(aex_stream_t *st, uint64_t offset, size_t length, void *buffer) {
    if (length == 0) return 0;
    uint8_t *dst = (uint8_t *)buffer;

    if (st->cb_read) {
        return st->cb_read(st->cb_ctx, offset, length, buffer);
    }

    if (st->kind == AEX_CONTAINER_SPARSEBUNDLE) {
        size_t done = 0;
        while (done < length) {
            uint64_t cur = offset + done;
            uint64_t bidx = cur / st->band_size;
            uint64_t boff = cur % st->band_size;
            size_t want = length - done;
            if (boff + want > st->band_size) want = (size_t)(st->band_size - boff);

            char bpath[1024];
            snprintf(bpath, sizeof(bpath), "%s/bands/%llx", st->bundle_dir, (unsigned long long)bidx);
            os_file_t bf;
            if (os_open_ro(bpath, &bf) != 0) {
                snprintf(bpath, sizeof(bpath), "%s/bands/%llX", st->bundle_dir, (unsigned long long)bidx);
                if (os_open_ro(bpath, &bf) != 0) {
                    /* Missing band file = sparse zeroes */
                    memset(dst + done, 0, want);
                    done += want;
                    continue;
                }
            }
            size_t got = 0;
            (void)os_pread_raw(&bf, boff, want, dst + done, &got);
            os_close(&bf);
            if (got < want) memset(dst + done + got, 0, want - got);
            done += want;
        }
        return 0;
    }

    if (st->kind == AEX_CONTAINER_SPARSEIMAGE) {
        size_t done = 0;
        while (done < length) {
            uint64_t cur = offset + done;
            uint64_t bidx = cur / st->band_size;
            uint64_t boff = cur % st->band_size;
            size_t want = length - done;
            if (boff + want > st->band_size) want = (size_t)(st->band_size - boff);

            if (bidx >= st->sprs_band_count || st->sprs_map[bidx] == 0) {
                memset(dst + done, 0, want);
            } else {
                uint64_t phys_off = st->sprs_data_start + (uint64_t)(st->sprs_map[bidx] - 1U) * st->band_size + boff;
                size_t got = 0;
                (void)os_pread_raw(&st->file, phys_off, want, dst + done, &got);
                if (got < want) memset(dst + done + got, 0, want - got);
            }
            done += want;
        }
        return 0;
    }

    if (st->kind == AEX_CONTAINER_UDIF_DMG) {
        size_t done = 0;
        while (done < length) {
            uint64_t cur = offset + done;
            size_t want = length - done;
            const udif_run_t *hit = NULL;
            for (size_t i = 0; i < st->dmg_run_count; i++) {
                if (cur >= st->dmg_runs[i].virt_off && cur < st->dmg_runs[i].virt_off + st->dmg_runs[i].virt_len) {
                    hit = &st->dmg_runs[i];
                    break;
                }
            }
            if (!hit || hit->type == 0x00000000U || hit->type == 0x00000002U) {
                size_t step = want;
                if (hit && (cur + step > hit->virt_off + hit->virt_len)) {
                    step = (size_t)(hit->virt_off + hit->virt_len - cur);
                } else if (!hit && step > 65536U) {
                    step = 65536U;
                }
                memset(dst + done, 0, step);
                done += step;
                continue;
            }
            uint64_t inner = cur - hit->virt_off;
            size_t step = want;
            if (inner + step > hit->virt_len) step = (size_t)(hit->virt_len - inner);

            if (hit->type == 0x00000001U) { /* Raw uncompressed run */
                if (os_pread_aligned(&st->file, hit->comp_off + inner, step, dst + done) != 0) return -EIO;
                done += step;
            } else if (hit->type == 0x80000005U || hit->type == 0x80000007U) { /* zlib or LZFSE */
                if (!st->dmg_cache_buf || st->dmg_cache_off != hit->virt_off || st->dmg_cache_len != hit->virt_len) {
                    if (hit->comp_len > (64ULL << 20) || hit->virt_len > (64ULL << 20)) return -ENOMEM;
                    uint8_t *cbuf = (uint8_t *)malloc((size_t)hit->comp_len);
                    uint8_t *ubuf = (uint8_t *)calloc(1, (size_t)hit->virt_len);
                    if (!cbuf || !ubuf) { free(cbuf); free(ubuf); return -ENOMEM; }
                    if (os_pread_aligned(&st->file, hit->comp_off, (size_t)hit->comp_len, cbuf) != 0) {
                        free(cbuf); free(ubuf); return -EIO;
                    }
                    size_t ugot = 0;
                    int rc = (hit->type == 0x80000005U)
                        ? aex_zlib_decompress(cbuf, (size_t)hit->comp_len, ubuf, (size_t)hit->virt_len, &ugot)
                        : aex_lzfse_decompress(cbuf, (size_t)hit->comp_len, ubuf, (size_t)hit->virt_len, &ugot);
                    free(cbuf);
                    if (rc != 0) { free(ubuf); return rc; }
                    free(st->dmg_cache_buf);
                    st->dmg_cache_buf = ubuf;
                    st->dmg_cache_off = hit->virt_off;
                    st->dmg_cache_len = hit->virt_len;
                }
                memcpy(dst + done, st->dmg_cache_buf + (size_t)inner, step);
                done += step;
            } else {
                return -ENOTSUP;
            }
        }
        return 0;
    }

    return os_pread_aligned(&st->file, offset, length, buffer);
}

int aex_stream_read(aex_stream_t *st, uint64_t offset, size_t length, void *buffer) {
    if (!st || (!buffer && length > 0)) return -EINVAL;
    if (length == 0) return 0;
    if (st->virtual_size > 0 && offset + length > st->virtual_size) return -EIO;

    if (!st->encrypted) {
        return stream_read_backing(st, offset, length, buffer);
    }

    /* Decrypt encrcdsa chunks (each chunk IV = first 16 bytes of HMAC-SHA1(hmac_key, be32(chunk_no))) */
    uint32_t csz = st->enc_chunk_size;
    uint64_t first_c = offset / csz;
    uint64_t last_c = (offset + length - 1ULL) / csz;
    uint8_t *cbuf = (uint8_t *)malloc(csz);
    uint8_t *pbuf = (uint8_t *)malloc(csz);
    if (!cbuf || !pbuf) { free(cbuf); free(pbuf); return -ENOMEM; }

    uint8_t *dst = (uint8_t *)buffer;
    size_t out_pos = 0;
    for (uint64_t c = first_c; c <= last_c; c++) {
        int rc = stream_read_backing(st, st->enc_data_offset + c * csz, csz, cbuf);
        if (rc != 0) { free(cbuf); free(pbuf); return rc; }
        uint8_t cno_be[4], mac[20];
        aex_put_be32(cno_be, (uint32_t)c);
        aex_hmac_sha1(st->enc_hmac_key, 20U, cno_be, 4U, mac);
        rc = aex_aes_cbc_decrypt(st->enc_aes_key, st->enc_aes_key_len, mac, cbuf, pbuf, csz);
        if (rc != 0) { free(cbuf); free(pbuf); return rc; }

        uint64_t c_start = c * csz;
        size_t inner = (offset + out_pos > c_start) ? (size_t)(offset + out_pos - c_start) : 0U;
        size_t take = csz - inner;
        if (out_pos + take > length) take = length - out_pos;
        memcpy(dst + out_pos, pbuf + inner, take);
        out_pos += take;
    }

    free(cbuf);
    free(pbuf);
    return 0;
}

int aex_slice_read(const aex_slice_t *sl, uint64_t off, size_t len, void *buf) {
    if (!sl || !sl->parent) return -EINVAL;
    if (sl->size > 0 && off + len > sl->size) return -EIO;
    return aex_stream_read(sl->parent, sl->offset + off, len, buf);
}

/* ---------------- Partition Discovery (GPT, APM, MBR, Whole) ---------------- */

static aex_fs_kind_t classify_slice_fs(const aex_slice_t *sl, char *label_out, size_t label_cap) {
    if (label_out && label_cap > 0) label_out[0] = '\0';
    if (aex_apfs_probe_slice(sl) == 0) {
        aex_volume_desc_t v;
        size_t cnt = 0;
        if (aex_apfs_list_volumes(sl, NULL, &v, 1U, &cnt) == 0 && cnt > 0 && label_out) {
            snprintf(label_out, label_cap, "%s", v.name);
        }
        return AEX_FS_APFS;
    }
    aex_fs_kind_t hk = AEX_FS_UNKNOWN;
    if (aex_hfs_probe_slice(sl, &hk, label_out, label_cap) == 0) {
        return hk;
    }
    return AEX_FS_UNKNOWN;
}

int aex_list_partitions(aex_stream_t *stream, aex_partition_desc_t *out_parts, size_t max_parts, size_t *out_count) {
    if (!stream || !out_count) return -EINVAL;
    *out_count = 0;
    uint64_t total_sz = aex_stream_size(stream);

    /* 1. Check direct filesystem at offset 0 (Partitionless) */
    aex_slice_t whole = { stream, 0ULL, total_sz };
    char wlabel[128] = "";
    aex_fs_kind_t wfs = classify_slice_fs(&whole, wlabel, sizeof(wlabel));
    if (wfs != AEX_FS_UNKNOWN) {
        if (out_parts && max_parts > 0) {
            memset(&out_parts[0], 0, sizeof(out_parts[0]));
            out_parts[0].index = 0;
            out_parts[0].offset_bytes = 0;
            out_parts[0].size_bytes = total_sz;
            out_parts[0].detected_fs = wfs;
            snprintf(out_parts[0].scheme, sizeof(out_parts[0].scheme), "Whole");
            snprintf(out_parts[0].type_str, sizeof(out_parts[0].type_str), "%s",
                     (wfs == AEX_FS_APFS) ? "Apple_APFS" : "Apple_HFS");
            snprintf(out_parts[0].name, sizeof(out_parts[0].name), "%s", wlabel[0] ? wlabel : "Volume");
        }
        *out_count = 1U;
        return 0;
    }

    /* 2. Check GPT at LBA 1 (sector size 512 or 4096) */
    const uint32_t sec_candidates[2] = { 512U, 4096U };
    for (int sc = 0; sc < 2; sc++) {
        uint32_t lba_sz = sec_candidates[sc];
        uint8_t ghdr[512];
        if (total_sz >= (uint64_t)lba_sz * 4ULL &&
            aex_stream_read(stream, lba_sz, sizeof(ghdr), ghdr) == 0 &&
            memcmp(ghdr, "EFI PART", 8) == 0) {
            uint64_t ent_lba = aex_le64(ghdr + 72U);
            uint32_t num_ent = aex_le32(ghdr + 80U);
            uint32_t ent_sz = aex_le32(ghdr + 84U);
            if (num_ent > 0 && num_ent <= 256U && ent_sz >= 128U && ent_sz <= 512U) {
                size_t tbl_bytes = (size_t)num_ent * (size_t)ent_sz;
                uint8_t *tbl = (uint8_t *)malloc(tbl_bytes);
                if (tbl && aex_stream_read(stream, ent_lba * lba_sz, tbl_bytes, tbl) == 0) {
                    size_t cnt = 0;
                    for (uint32_t i = 0; i < num_ent; i++) {
                        const uint8_t *e = tbl + (size_t)i * ent_sz;
                        int all_zero = 1;
                        for (int b = 0; b < 16; b++) if (e[b] != 0) { all_zero = 0; break; }
                        if (all_zero) continue;
                        uint64_t first_lba = aex_le64(e + 32U);
                        uint64_t last_lba = aex_le64(e + 40U);
                        if (last_lba < first_lba) continue;
                        uint64_t poff = first_lba * lba_sz;
                        uint64_t psz = (last_lba - first_lba + 1ULL) * lba_sz;
                        if (total_sz > 0 && poff + psz > total_sz) continue;

                        if (out_parts && cnt < max_parts) {
                            aex_partition_desc_t *pd = &out_parts[cnt];
                            memset(pd, 0, sizeof(*pd));
                            pd->index = (uint32_t)cnt;
                            pd->offset_bytes = poff;
                            pd->size_bytes = psz;
                            snprintf(pd->scheme, sizeof(pd->scheme), "GPT");
                            /* Decode UTF-16LE name at e + 56 (36 chars) */
                            size_t np = 0;
                            for (int c = 0; c < 36 && np + 1 < sizeof(pd->name); c++) {
                                uint16_t ch = aex_le16(e + 56U + c * 2U);
                                if (ch == 0) break;
                                pd->name[np++] = (ch < 128U) ? (char)ch : '?';
                            }
                            pd->name[np] = '\0';
                            aex_slice_t psl = { stream, poff, psz };
                            char lbl[128] = "";
                            pd->detected_fs = classify_slice_fs(&psl, lbl, sizeof(lbl));
                            if (lbl[0] && !pd->name[0]) snprintf(pd->name, sizeof(pd->name), "%s", lbl);
                            snprintf(pd->type_str, sizeof(pd->type_str), "%s",
                                     (pd->detected_fs == AEX_FS_APFS) ? "Apple_APFS"
                                   : (pd->detected_fs != AEX_FS_UNKNOWN) ? "Apple_HFS" : "GPT Partition");
                        }
                        cnt++;
                    }
                    free(tbl);
                    if (cnt > 0) {
                        *out_count = cnt;
                        return 0;
                    }
                } else {
                    free(tbl);
                }
            }
        }
    }

    /* 3. Check Apple Partition Map (APM, 'PM' 0x504D at sector 1 = offset 512) */
    uint8_t pm[512];
    if (total_sz >= 2048ULL && aex_stream_read(stream, 512ULL, sizeof(pm), pm) == 0 &&
        aex_be16(pm) == 0x504DU) {
        uint32_t map_entries = aex_be32(pm + 4U);
        if (map_entries > 0 && map_entries <= 64U) {
            size_t cnt = 0;
            for (uint32_t i = 1; i <= map_entries; i++) {
                if (aex_stream_read(stream, (uint64_t)i * 512ULL, sizeof(pm), pm) != 0) break;
                if (aex_be16(pm) != 0x504DU) break;
                uint32_t pstart = aex_be32(pm + 8U);
                uint32_t pblocks = aex_be32(pm + 12U);
                uint64_t poff = (uint64_t)pstart * 512ULL;
                uint64_t psz = (uint64_t)pblocks * 512ULL;
                if (psz == 0 || (total_sz > 0 && poff + psz > total_sz)) continue;

                if (out_parts && cnt < max_parts) {
                    aex_partition_desc_t *pd = &out_parts[cnt];
                    memset(pd, 0, sizeof(*pd));
                    pd->index = (uint32_t)cnt;
                    pd->offset_bytes = poff;
                    pd->size_bytes = psz;
                    snprintf(pd->scheme, sizeof(pd->scheme), "APM");
                    memcpy(pd->name, pm + 16U, 32U); pd->name[32] = '\0';
                    memcpy(pd->type_str, pm + 48U, 32U); pd->type_str[32] = '\0';
                    aex_slice_t psl = { stream, poff, psz };
                    char lbl[128] = "";
                    pd->detected_fs = classify_slice_fs(&psl, lbl, sizeof(lbl));
                    if (lbl[0]) snprintf(pd->name, sizeof(pd->name), "%s", lbl);
                }
                cnt++;
            }
            if (cnt > 0) {
                *out_count = cnt;
                return 0;
            }
        }
    }

    /* 4. Check MBR at offset 0 */
    uint8_t mbr[512];
    if (total_sz >= 512ULL && aex_stream_read(stream, 0ULL, sizeof(mbr), mbr) == 0 &&
        mbr[510] == 0x55U && mbr[511] == 0xAAU) {
        size_t cnt = 0;
        for (int i = 0; i < 4; i++) {
            const uint8_t *pe = mbr + 446U + i * 16U;
            uint8_t ptype = pe[4];
            uint32_t lba = aex_le32(pe + 8U);
            uint32_t secs = aex_le32(pe + 12U);
            if (ptype == 0 || ptype == 0xEEU || secs == 0) continue;
            uint64_t poff = (uint64_t)lba * 512ULL;
            uint64_t psz = (uint64_t)secs * 512ULL;
            if (total_sz > 0 && poff + psz > total_sz) continue;
            if (out_parts && cnt < max_parts) {
                aex_partition_desc_t *pd = &out_parts[cnt];
                memset(pd, 0, sizeof(*pd));
                pd->index = (uint32_t)cnt;
                pd->offset_bytes = poff;
                pd->size_bytes = psz;
                snprintf(pd->scheme, sizeof(pd->scheme), "MBR");
                snprintf(pd->type_str, sizeof(pd->type_str), "0x%02X", ptype);
                aex_slice_t psl = { stream, poff, psz };
                pd->detected_fs = classify_slice_fs(&psl, pd->name, sizeof(pd->name));
            }
            cnt++;
        }
        if (cnt > 0) {
            *out_count = cnt;
            return 0;
        }
    }

    return -ENOENT;
}

/* ---------------- Top-Level Probe, Volume List, Open, and Recursive Extract ---------------- */

const char *aex_version(void) { return AEX_VERSION; }

const char *aex_strerror(int err_code) {
    int pos = (err_code < 0) ? -err_code : err_code;
    return strerror(pos);
}

static int select_apple_slice(aex_stream_t *st, int partition_index, aex_slice_t *out_slice, aex_fs_kind_t *out_kind) {
    aex_partition_desc_t parts[32];
    size_t pcnt = 0;
    if (aex_list_partitions(st, parts, 32U, &pcnt) == 0 && pcnt > 0) {
        size_t max_check = (pcnt < 32U) ? pcnt : 32U;
        if (partition_index >= 0) {
            if ((size_t)partition_index >= max_check) return -ENOENT;
            out_slice->parent = st;
            out_slice->offset = parts[partition_index].offset_bytes;
            out_slice->size = parts[partition_index].size_bytes;
            *out_kind = parts[partition_index].detected_fs;
            return (*out_kind != AEX_FS_UNKNOWN) ? 0 : -EINVAL;
        }
        for (size_t i = 0; i < max_check; i++) {
            if (parts[i].detected_fs != AEX_FS_UNKNOWN) {
                out_slice->parent = st;
                out_slice->offset = parts[i].offset_bytes;
                out_slice->size = parts[i].size_bytes;
                *out_kind = parts[i].detected_fs;
                return 0;
            }
        }
    }
    return -EINVAL;
}

int aex_probe_path(const char *path, const char *password, aex_probe_info_t *out_info) {
    if (!path || !out_info) return -EINVAL;
    memset(out_info, 0, sizeof(*out_info));

    aex_stream_t *st = NULL;
    int rc = aex_stream_open_path(path, password, &st);
    if (rc != 0) return rc;

    out_info->container_kind = st->kind;
    out_info->container_encrypted = st->encrypted;
    out_info->virtual_size = st->virtual_size;
    out_info->band_size = st->band_size;

    aex_partition_desc_t parts[32];
    size_t pcnt = 0;
    if (aex_list_partitions(st, parts, 32U, &pcnt) == 0) {
        out_info->partition_count = (uint32_t)pcnt;
    }

    aex_slice_t sl;
    aex_fs_kind_t fk = AEX_FS_UNKNOWN;
    if (select_apple_slice(st, -1, &sl, &fk) == 0) {
        out_info->primary_fs = fk;
        if (fk == AEX_FS_APFS) {
            aex_volume_desc_t vols[16];
            size_t vcnt = 0;
            if (aex_apfs_list_volumes(&sl, password, vols, 16U, &vcnt) == 0 && vcnt > 0) {
                out_info->volume_count = (uint32_t)vcnt;
                snprintf(out_info->primary_label, sizeof(out_info->primary_label), "%s", vols[0].name);
                for (size_t v = 0; v < vcnt && v < 16U; v++) {
                    if (vols[v].snapshot_count > 0) out_info->has_apfs_snapshots = 1;
                }
            }
        } else {
            out_info->volume_count = 1U;
            (void)aex_hfs_probe_slice(&sl, &fk, out_info->primary_label, sizeof(out_info->primary_label));
        }
    }

    aex_stream_close(st);

    /* Check if /Backups.backupdb exists on HFS+ */
    if (out_info->primary_fs == AEX_FS_HFSPLUS) {
        aex_open_options_t o = { -1, -1, NULL, password };
        aex_t *fs = NULL;
        if (aex_open_path(path, &o, &fs) == 0) {
            uint64_t bino = 0;
            if (aex_lookup_path(fs, "/Backups.backupdb", &bino) == 0) {
                out_info->has_backups_db = 1;
            }
            aex_close(fs);
        }
    }
    return (out_info->primary_fs != AEX_FS_UNKNOWN || out_info->partition_count > 0) ? 0 : -EINVAL;
}

int aex_list_volumes_path(const char *path, const char *password, aex_volume_desc_t *out_vols, size_t max_vols, size_t *out_count) {
    if (!path || !out_count) return -EINVAL;
    *out_count = 0;
    aex_stream_t *st = NULL;
    int rc = aex_stream_open_path(path, password, &st);
    if (rc != 0) return rc;

    aex_slice_t sl;
    aex_fs_kind_t fk = AEX_FS_UNKNOWN;
    rc = select_apple_slice(st, -1, &sl, &fk);
    if (rc == 0) {
        if (fk == AEX_FS_APFS) {
            rc = aex_apfs_list_volumes(&sl, password, out_vols, max_vols, out_count);
        } else {
            char lbl[128] = "";
            (void)aex_hfs_probe_slice(&sl, &fk, lbl, sizeof(lbl));
            if (out_vols && max_vols > 0) {
                memset(&out_vols[0], 0, sizeof(out_vols[0]));
                out_vols[0].index = 0;
                out_vols[0].kind = fk;
                out_vols[0].total_bytes = sl.size;
                snprintf(out_vols[0].name, sizeof(out_vols[0].name), "%s", lbl[0] ? lbl : "Macintosh HD");
                snprintf(out_vols[0].role, sizeof(out_vols[0].role), "Data");
            }
            *out_count = 1U;
        }
    }
    aex_stream_close(st);
    return rc;
}

static int open_from_stream(aex_stream_t *st, int owns_stream, const aex_open_options_t *opts, aex_t **out_fs) {
    int p_idx = opts ? opts->partition_index : -1;
    int v_idx = opts ? opts->volume_index : -1;
    const char *snap = opts ? opts->snapshot_name : NULL;
    const char *pass = opts ? opts->password : NULL;

    aex_slice_t sl;
    aex_fs_kind_t fk = AEX_FS_UNKNOWN;
    int rc = select_apple_slice(st, p_idx, &sl, &fk);
    if (rc != 0) {
        if (owns_stream) aex_stream_close(st);
        return rc;
    }

    aex_t *h = (aex_t *)calloc(1, sizeof(aex_t));
    if (!h) {
        if (owns_stream) aex_stream_close(st);
        return -ENOMEM;
    }
    h->owned_stream = owns_stream ? st : NULL;
    h->slice = sl;
    h->kind = fk;

    if (fk == AEX_FS_APFS) {
        rc = aex_apfs_open(h, v_idx, snap, pass);
    } else {
        rc = aex_hfs_open(h);
    }
    if (rc != 0) {
        if (owns_stream) aex_stream_close(st);
        free(h);
        return rc;
    }
    *out_fs = h;
    return 0;
}

int aex_open_path(const char *path, const aex_open_options_t *opts, aex_t **out_fs) {
    if (!path || !out_fs) return -EINVAL;
    *out_fs = NULL;
    aex_stream_t *st = NULL;
    int rc = aex_stream_open_path(path, opts ? opts->password : NULL, &st);
    if (rc != 0) return rc;
    return open_from_stream(st, 1, opts, out_fs);
}

int aex_open_io(aex_read_fn read_fn, void *io_ctx, uint64_t size_bytes, const aex_open_options_t *opts, aex_t **out_fs) {
    if (!read_fn || !out_fs) return -EINVAL;
    *out_fs = NULL;
    aex_stream_t *st = NULL;
    int rc = aex_stream_open_io(read_fn, io_ctx, size_bytes, &st);
    if (rc != 0) return rc;
    return open_from_stream(st, 1, opts, out_fs);
}

void aex_close(aex_t *fs) {
    if (!fs) return;
    if (fs->ops && fs->ops->close_priv) fs->ops->close_priv(fs->priv);
    if (fs->owned_stream) aex_stream_close(fs->owned_stream);
    free(fs);
}

aex_fs_kind_t aex_fs_kind(const aex_t *fs) { return fs ? fs->kind : AEX_FS_UNKNOWN; }
const char *aex_volume_name(const aex_t *fs) { return fs ? fs->vol_name : ""; }
uint64_t aex_root_ino(const aex_t *fs) { return (fs && fs->ops) ? fs->ops->root_ino(fs->priv) : 0ULL; }

int aex_list_snapshots(aex_t *fs, aex_snapshot_desc_t *out_snaps, size_t max_snaps, size_t *out_count) {
    if (!fs || !out_count) return -EINVAL;
    if (!fs->ops->list_snapshots) { *out_count = 0; return 0; }
    return fs->ops->list_snapshots(fs->priv, out_snaps, max_snaps, out_count);
}

int aex_statfs(aex_t *fs, uint64_t *total_bytes, uint64_t *used_bytes, uint32_t *block_size) {
    if (!fs || !fs->ops) return -EINVAL;
    return fs->ops->statfs(fs->priv, total_bytes, used_bytes, block_size);
}

int aex_getattr(aex_t *fs, uint64_t ino, aex_attr_t *out_attr) {
    if (!fs || !fs->ops || !out_attr) return -EINVAL;
    return fs->ops->getattr(fs->priv, ino, out_attr);
}

int aex_readdir(aex_t *fs, uint64_t dir_ino, aex_readdir_cb cb, void *user_ctx) {
    if (!fs || !fs->ops || !cb) return -EINVAL;
    return fs->ops->readdir(fs->priv, dir_ino, cb, user_ctx);
}

int aex_lookup(aex_t *fs, uint64_t dir_ino, const char *name, uint64_t *out_ino) {
    if (!fs || !fs->ops || !name || !out_ino) return -EINVAL;
    return fs->ops->lookup(fs->priv, dir_ino, name, out_ino);
}

int aex_lookup_path(aex_t *fs, const char *path, uint64_t *out_ino) {
    if (!fs || !path || !out_ino) return -EINVAL;
    uint64_t cur = aex_root_ino(fs);
    const char *p = path;
    while (*p == '/' || *p == '\\') p++;
    while (*p != '\0') {
        const char *sep = p;
        while (*sep && *sep != '/' && *sep != '\\') sep++;
        size_t len = (size_t)(sep - p);
        if (len > 255U) return -ENAMETOOLONG;
        char seg[256];
        memcpy(seg, p, len);
        seg[len] = '\0';
        if (strcmp(seg, ".") != 0) {
            uint64_t next = 0;
            int rc = aex_lookup(fs, cur, seg, &next);
            if (rc != 0) return rc;
            cur = next;
        }
        p = sep;
        while (*p == '/' || *p == '\\') p++;
    }
    *out_ino = cur;
    return 0;
}

int aex_read(aex_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    if (!fs || !fs->ops || !out_read || (!buffer && length > 0)) return -EINVAL;
    return fs->ops->read_data(fs->priv, ino, 0, offset, length, buffer, out_read);
}

int aex_read_rsrc(aex_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    if (!fs || !fs->ops || !out_read || (!buffer && length > 0)) return -EINVAL;
    return fs->ops->read_data(fs->priv, ino, 1, offset, length, buffer, out_read);
}

int aex_readlink(aex_t *fs, uint64_t ino, char *buffer, size_t buffer_cap, size_t *out_len) {
    if (!fs || !fs->ops || !buffer || buffer_cap == 0) return -EINVAL;
    return fs->ops->readlink(fs->priv, ino, buffer, buffer_cap, out_len);
}

/* Recursive Extraction Helper */
typedef struct {
    aex_t      *fs;
    const char *dest_dir;
    int         depth;
    int         err;
} extract_dir_ctx_t;

static int extract_node(aex_t *fs, uint64_t ino, const char *dest_path, int depth);

static int extract_dir_cb(void *user_ctx, const char *name, uint64_t ino, aex_ftype_t ftype) {
    (void)ftype;
    extract_dir_ctx_t *ec = (extract_dir_ctx_t *)user_ctx;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return 0;
    /* Sanitize path separators or control chars in extracted host filename */
    char safe[256];
    size_t sp = 0;
    for (size_t i = 0; name[i] && sp + 1 < sizeof(safe); i++) {
        char c = name[i];
        if (c == '/' || c == '\\' || (unsigned char)c < 32U) c = '_';
#ifdef _WIN32
        if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') c = '_';
#endif
        safe[sp++] = c;
    }
    safe[sp] = '\0';
    if (sp == 0) return 0;

    char child_dest[2048];
    snprintf(child_dest, sizeof(child_dest), "%s/%s", ec->dest_dir, safe);
    int rc = extract_node(ec->fs, ino, child_dest, ec->depth + 1);
    if (rc != 0) { ec->err = rc; return 1; }
    return 0;
}

static int extract_node(aex_t *fs, uint64_t ino, const char *dest_path, int depth) {
    if (depth > 64) return -ELOOP;
    aex_attr_t attr;
    int rc = aex_getattr(fs, ino, &attr);
    if (rc != 0) return rc;

    if (attr.ftype == AEX_FT_DIR) {
        rc = os_mkdir_one(dest_path);
        if (rc != 0) return rc;
        extract_dir_ctx_t ec = { fs, dest_path, depth, 0 };
        rc = aex_readdir(fs, ino, extract_dir_cb, &ec);
        return (rc != 0) ? rc : ec.err;
    } else if (attr.ftype == AEX_FT_REG) {
        FILE *fp = fopen(dest_path, "wb");
        if (!fp) return -errno;
        uint8_t *buf = (uint8_t *)malloc(65536U);
        if (!buf) { fclose(fp); return -ENOMEM; }
        uint64_t off = 0;
        while (off < attr.size) {
            size_t got = 0;
            rc = aex_read(fs, ino, off, 65536U, buf, &got);
            if (rc != 0) { free(buf); fclose(fp); return rc; }
            if (got == 0) break;
            if (fwrite(buf, 1U, got, fp) != got) { free(buf); fclose(fp); return -EIO; }
            off += got;
        }
        free(buf);
        fclose(fp);
        return 0;
    } else if (attr.ftype == AEX_FT_SYMLINK) {
        char target[1024];
        size_t tlen = 0;
        if (aex_readlink(fs, ino, target, sizeof(target), &tlen) == 0) {
#ifdef _WIN32
            FILE *fp = fopen(dest_path, "wb");
            if (fp) {
                size_t wl = strlen(target);
                if (fwrite(target, 1U, wl, fp) != wl) { /* best-effort symlink stub */ }
                fclose(fp);
            }
#else
            if (unlink(dest_path) != 0) { /* ignore missing target */ }
            if (symlink(target, dest_path) != 0) { /* best-effort symlink */ }
#endif
        }
        return 0;
    }
    return 0;
}

int aex_extract_path(aex_t *fs, const char *src_path, const char *dest_host_path) {
    if (!fs || !src_path || !dest_host_path) return -EINVAL;
    uint64_t ino = 0;
    int rc = aex_lookup_path(fs, src_path, &ino);
    if (rc != 0) return rc;
    return extract_node(fs, ino, dest_host_path, 0);
}
