#ifndef _MD5_H_
#define _MD5_H_
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// -----------------------------------------------------------------------------
// Usage:

static void md5_hexdigest(const char *input, char output[33]);

// -----------------------------------------------------------------------------
// Implementation:

#define MD5_BLOCK  64 // Bytes
#define MD5_DIGEST 16 // Bytes
typedef struct _md5_ctx {
	uint32_t count[2];
	uint32_t state[4];
	uint8_t  buffer[MD5_BLOCK];
	uint8_t  digest[MD5_DIGEST];
} _md5_ctx;

static void _decode(uint32_t *output, const uint8_t *input, uint64_t len);
static void _encode(uint8_t *output, const uint32_t *input, uint64_t len);
static void _md5_init(_md5_ctx *ctx);
static void _md5_transform(_md5_ctx *ctx, const uint8_t block[MD5_BLOCK]);
static void _md5_update(_md5_ctx *ctx, const uint8_t *input, uint64_t len);
static void _md5_final(_md5_ctx *ctx);

static void md5_hexdigest(const char *input, char output[33]) {
	_md5_ctx ctx = {0};
	_md5_init(&ctx);
	_md5_update(&ctx, (uint8_t *)input, (uint64_t)strlen(input));
	_md5_final(&ctx);
	for (int i = 0; i < 16; i++) sprintf((output + i * 2), "%02x", ctx.digest[i]);
	output[32] = '\0';
}

#define MD5_F(x, y, z) ((x & y) | (~x & z))
#define MD5_G(x, y, z) ((x & z) | (y & ~z))
#define MD5_H(x, y, z) (x ^ y ^ z)
#define MD5_I(x, y, z) (y ^ (x | ~z))

#define MD5_ROT_LEFT(x, n) ((x << n) | (x >> (32 - n)))
#define MD5_FF(a, b, c, d, x, s, ac) \
	(MD5_ROT_LEFT((a + MD5_F(b, c, d) + x + ac), s) + b)
#define MD5_GG(a, b, c, d, x, s, ac) \
	(MD5_ROT_LEFT((a + MD5_G(b, c, d) + x + ac), s) + b)
#define MD5_HH(a, b, c, d, x, s, ac) \
	(MD5_ROT_LEFT((a + MD5_H(b, c, d) + x + ac), s) + b)
#define MD5_II(a, b, c, d, x, s, ac) \
	(MD5_ROT_LEFT((a + MD5_I(b, c, d) + x + ac), s) + b)

static void _md5_init(_md5_ctx *ctx) {
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

static void _decode(uint32_t *output, const uint8_t *input, uint64_t len) {
	for (uint32_t i = 0, j = 0; j < len; i++, j += 4)
		output[i]
		  = ((uint32_t)input[j] | ((uint32_t)input[j + 1] << 8)
		     | ((uint32_t)input[j + 2] << 16) | ((uint32_t)input[j + 3] << 24));
}

static void _encode(uint8_t *output, const uint32_t *input, uint64_t len) {
	for (uint32_t i = 0, j = 0; j < len; i++, j += 4) {
		output[j]     = (input[i] >> 0) & 0xff;
		output[j + 1] = (input[i] >> 8) & 0xff;
		output[j + 2] = (input[i] >> 16) & 0xff;
		output[j + 3] = (input[i] >> 24) & 0xff;
	}
}

static void _md5_transform(_md5_ctx *ctx, const uint8_t block[MD5_BLOCK]) {
	uint32_t a = ctx->state[0];
	uint32_t b = ctx->state[1];
	uint32_t c = ctx->state[2];
	uint32_t d = ctx->state[3];
	uint32_t x[16];
	_decode(x, block, MD5_BLOCK);
	// clang-format off
	{ // Round 1
		a = MD5_FF(a, b, c, d, x [0],  7, 0xd76aa478);
		d = MD5_FF(d, a, b, c, x [1], 12, 0xe8c7b756);
		c = MD5_FF(c, d, a, b, x [2], 17, 0x242070db);
		b = MD5_FF(b, c, d, a, x [3], 22, 0xc1bdceee);
		a = MD5_FF(a, b, c, d, x [4],  7, 0xf57c0faf);
		d = MD5_FF(d, a, b, c, x [5], 12, 0x4787c62a);
		c = MD5_FF(c, d, a, b, x [6], 17, 0xa8304613);
		b = MD5_FF(b, c, d, a, x [7], 22, 0xfd469501);
		a = MD5_FF(a, b, c, d, x [8],  7, 0x698098d8);
		d = MD5_FF(d, a, b, c, x [9], 12, 0x8b44f7af);
		c = MD5_FF(c, d, a, b, x[10], 17, 0xffff5bb1);
		b = MD5_FF(b, c, d, a, x[11], 22, 0x895cd7be);
		a = MD5_FF(a, b, c, d, x[12],  7, 0x6b901122);
		d = MD5_FF(d, a, b, c, x[13], 12, 0xfd987193);
		c = MD5_FF(c, d, a, b, x[14], 17, 0xa679438e);
		b = MD5_FF(b, c, d, a, x[15], 22, 0x49b40821);
	}	{ // Round 2
		a = MD5_GG(a, b, c, d, x [1],  5, 0xf61e2562);
		d = MD5_GG(d, a, b, c, x [6],  9, 0xc040b340);
		c = MD5_GG(c, d, a, b, x[11], 14, 0x265e5a51);
		b = MD5_GG(b, c, d, a, x [0], 20, 0xe9b6c7aa);
		a = MD5_GG(a, b, c, d, x [5],  5, 0xd62f105d);
		d = MD5_GG(d, a, b, c, x[10],  9, 0x02441453);
		c = MD5_GG(c, d, a, b, x[15], 14, 0xd8a1e681);
		b = MD5_GG(b, c, d, a, x [4], 20, 0xe7d3fbc8);
		a = MD5_GG(a, b, c, d, x [9],  5, 0x21e1cde6);
		d = MD5_GG(d, a, b, c, x[14],  9, 0xc33707d6);
		c = MD5_GG(c, d, a, b, x [3], 14, 0xf4d50d87);
		b = MD5_GG(b, c, d, a, x [8], 20, 0x455a14ed);
		a = MD5_GG(a, b, c, d, x[13],  5, 0xa9e3e905);
		d = MD5_GG(d, a, b, c, x [2],  9, 0xfcefa3f8);
		c = MD5_GG(c, d, a, b, x [7], 14, 0x676f02d9);
		b = MD5_GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);
	}	{ // Round 3
		a = MD5_HH(a, b, c, d, x [5],  4, 0xfffa3942);
		d = MD5_HH(d, a, b, c, x [8], 11, 0x8771f681);
		c = MD5_HH(c, d, a, b, x[11], 16, 0x6d9d6122);
		b = MD5_HH(b, c, d, a, x[14], 23, 0xfde5380c);
		a = MD5_HH(a, b, c, d, x [1],  4, 0xa4beea44);
		d = MD5_HH(d, a, b, c, x [4], 11, 0x4bdecfa9);
		c = MD5_HH(c, d, a, b, x [7], 16, 0xf6bb4b60);
		b = MD5_HH(b, c, d, a, x[10], 23, 0xbebfbc70);
		a = MD5_HH(a, b, c, d, x[13],  4, 0x289b7ec6);
		d = MD5_HH(d, a, b, c, x [0], 11, 0xeaa127fa);
		c = MD5_HH(c, d, a, b, x [3], 16, 0xd4ef3085);
		b = MD5_HH(b, c, d, a, x [6], 23, 0x04881d05);
		a = MD5_HH(a, b, c, d, x [9],  4, 0xd9d4d039);
		d = MD5_HH(d, a, b, c, x[12], 11, 0xe6db99e5);
		c = MD5_HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
		b = MD5_HH(b, c, d, a, x[2] , 23, 0xc4ac5665);
	}	{ // Round 4
		a = MD5_II(a, b, c, d, x [0],  6, 0xf4292244);
		d = MD5_II(d, a, b, c, x [7], 10, 0x432aff97);
		c = MD5_II(c, d, a, b, x[14], 15, 0xab9423a7);
		b = MD5_II(b, c, d, a, x [5], 21, 0xfc93a039);
		a = MD5_II(a, b, c, d, x[12],  6, 0x655b59c3);
		d = MD5_II(d, a, b, c, x [3], 10, 0x8f0ccc92);
		c = MD5_II(c, d, a, b, x[10], 15, 0xffeff47d);
		b = MD5_II(b, c, d, a, x [1], 21, 0x85845dd1);
		a = MD5_II(a, b, c, d, x [8],  6, 0x6fa87e4f);
		d = MD5_II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
		c = MD5_II(c, d, a, b, x [6], 15, 0xa3014314);
		b = MD5_II(b, c, d, a, x[13], 21, 0x4e0811a1);
		a = MD5_II(a, b, c, d, x [4],  6, 0xf7537e82);
		d = MD5_II(d, a, b, c, x[11], 10, 0xbd3af235);
		c = MD5_II(c, d, a, b, x [2], 15, 0x2ad7d2bb);
		b = MD5_II(b, c, d, a, x [9], 21, 0xeb86d391);
	} // clang-format on
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	// memset(x, 0, sizeof(x)); // Let's not pretend it's secure.
}

static void _md5_update(_md5_ctx *ctx, const uint8_t *input, uint64_t len) {
	// Bytes mod 64
	// uint64_t index = (ctx->count[0] >> 3) & 0x3F; // Equivalent to below
	uint64_t index = (ctx->count[0] / 8) % MD5_BLOCK; // Let compiler do its thing
	// Update bit count
	if ((ctx->count[0] += len << 3) < len << 3) ctx->count[1]++;
	ctx->count[1] += len >> 29;
	// Handle any leading odd-sized chunks
	uint64_t first_part = MD5_BLOCK - index;
	uint64_t i;
	if (len >= first_part) {
		memcpy(ctx->buffer + index, input, first_part);
		_md5_transform(ctx, ctx->buffer);
		// Keep on transforming
		for (i = first_part; i + MD5_BLOCK <= len; i += MD5_BLOCK)
			_md5_transform(ctx, &input[i]);
		// Done
		index = 0;
	} else i = 0;
	// Deal with remaining bytes
	memcpy(ctx->buffer + index, input + i, len - i);
}

static void _md5_final(_md5_ctx *ctx) {
	const uint8_t padding[MD5_BLOCK]
	  = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	     0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	     0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint8_t bits[8];
	_encode(bits, ctx->count, 8);
	uint64_t index   = (ctx->count[0] / 8) % MD5_BLOCK;
	uint64_t pad_len = (index < 56) ? 56 - index : 120 - index; // 56 mod 64
	_md5_update(ctx, padding, pad_len);
	_md5_update(ctx, bits, 8); // len before padding
	_encode(ctx->digest, ctx->state, 16);
	// Let's not pretend to be secure
	// memset(ctx->buffer, 0, sizeof(ctx->buffer));
	// memset(ctx->count, 0, sizeof(ctx->count));
}

#endif // _MD5_H_
