#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "base64.h"

#ifdef USE_OPENSSL

#include <openssl/evp.h>

size_t b64_encode(const char *s, size_t nbytes, char **pdst, int breaks, int cr)
{
	if (!pdst)
		return 0;

	// EVP_EncodeBlock output size: 4 * ceil(n/3) + 1
	size_t max_len = ((nbytes + 2) / 3) * 4 + 1;

	// Account for line breaks if requested (every 76 chars)
	if (breaks)
		max_len += (max_len / 76) * (cr ? 2 : 1);

	if (!*pdst) {
		*pdst = malloc(max_len);
		if (!*pdst) return 0;
	}

	int len = EVP_EncodeBlock((unsigned char *)*pdst, (const unsigned char *)s, (int)nbytes);

	if (len < 0) {
		return 0;
	}

	// Add line breaks if requested
	if (breaks && len > 76) {
		char *tmp = malloc(max_len);
		if (!tmp) return 0;

		char *src = *pdst;
		char *dst = tmp;
		int line_len = 0;

		for (int i = 0; i < len; i++) {
			*dst++ = src[i];
			line_len++;

			if (line_len >= 76 && i < len - 1) {
				if (cr) *dst++ = '\r';
				*dst++ = '\n';
				line_len = 0;
			}
		}
		*dst = '\0';

		size_t final_len = dst - tmp;
		memcpy(*pdst, tmp, final_len + 1);
		free(tmp);
		return final_len;
	}

	return (size_t)len;
}

size_t b64_decode(const char *s, size_t nbytes, char **pdst)
{
	if (!pdst)
		return 0;

	// Skip whitespace and count valid base64 chars
	size_t valid_len = 0;
	for (size_t i = 0; i < nbytes; i++) {
		char c = s[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')
			valid_len++;
	}

	// EVP_DecodeBlock output size: 3 * ceil(n/4)
	size_t max_len = (valid_len / 4) * 3 + 3;

	// Need clean input without whitespace for EVP_DecodeBlock
	char *clean = malloc(valid_len + 1);
	if (!clean) return 0;

	size_t j = 0;
	for (size_t i = 0; i < nbytes; i++) {
		char c = s[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')
			clean[j++] = c;
	}
	clean[j] = '\0';

	if (!*pdst) {
		*pdst = malloc(max_len);
		if (!*pdst) {
			free(clean);
			return 0;
		}
	}

	// Count padding for length adjustment
	int padding = 0;
	if (j > 0 && clean[j - 1] == '=') padding++;
	if (j > 1 && clean[j - 2] == '=') padding++;

	int len = EVP_DecodeBlock((unsigned char *)*pdst, (const unsigned char *)clean, (int)valid_len);
	free(clean);

	if (len < 0) {
		return 0;
	}

	// EVP_DecodeBlock doesn't account for padding, adjust length
	len -= padding;

	(*pdst)[len] = '\0';
	return (size_t)len;
}

#else /* !USE_OPENSSL */

static size_t encode_base64(char *ostr, uint8_t *inbuf, int *inbuf_size, int *line_len, int breaks, int cr)
{
	static const uint8_t vec[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	static const uint8_t padding = '=';
	uint8_t out;
	size_t len = 0;

	out = (uint8_t)((*(inbuf+0) & 0xFC) >> 2);
	*ostr++ = vec[out];
	out = (uint8_t)(((*(inbuf+0) & 0x03) << 4) | (*(inbuf+1) >> 4));
	*ostr++ = vec[out];
	out = (uint8_t)(((*(inbuf+1) & 0x0F) << 2) | (*(inbuf+2) >> 6));
	*ostr++ = (*inbuf_size > 1 ? vec[out] : padding);
	out = (uint8_t)(*(inbuf+2) & 0x3F);
	*ostr++ = (*inbuf_size > 2 ? vec[out] : padding);
	*line_len += 4;
	len = 4;

	if ((*line_len >= 76) && breaks) {
		if (cr)
			*ostr++ = '\r';

		*ostr++ = '\n';
		*line_len = 0;
		len++;
	}

	*inbuf_size = 0;
	return len;
}

size_t b64_encode(const char *s, size_t nbytes, char **pdst, int breaks, int cr)
{
	if (!pdst)
		return 0;

	size_t max_len = 0, bytes_left = 0;

	if (!*pdst) {
		*pdst = malloc(max_len=bytes_left=64);
		if (!*pdst) return 0;
	}

	char *dst = *pdst;
	int inbuf_size = 0, line_len = 0;
	uint8_t inbuf[4];

	for (size_t i = 0; i < nbytes; i++) {
		inbuf[inbuf_size++] = s[i];

		if (inbuf_size == 3) {
			size_t len = encode_base64(dst, inbuf, &inbuf_size, &line_len, breaks, cr);
			dst += len;
			bytes_left -= len;
		}

		if (max_len && (bytes_left < 8)) {
			max_len *= 2;
			size_t nbytes = dst - *pdst;
			bytes_left = max_len - nbytes;
			*pdst = realloc(*pdst, max_len);
			if (!*pdst) return 0;
			dst = *pdst + nbytes;
		}
	}

	if (inbuf_size) {
		for (int i = inbuf_size; i < 3; i++)
			inbuf[i] = 0;

		dst += encode_base64(dst, inbuf, &inbuf_size, &line_len, breaks, cr);
	}

	*dst = 0;
	return dst - *pdst;
}

static size_t decode_base64(char *ostr, const uint8_t *inbuf, int *inbuf_size)
{
	uint8_t out;
	size_t len = 0;

	out = (uint8_t)((*(inbuf+0) << 2) | (*(inbuf+1) >> 4));
	*ostr++ = out;
	len++;

	if (*inbuf_size > 2) {
		out = (uint8_t)((*(inbuf+1) << 4) | (*(inbuf+2) >> 2));
		*ostr++ = out;
		len++;
	}

	if (*inbuf_size > 3) {
		out = (uint8_t)((*(inbuf+2) << 6) | *(inbuf+3));
		*ostr++ = out;
		len++;
	}

	*inbuf_size = 0;
	return len;
}

static int conv_to_number(uint8_t inbyte)
{
	if (inbyte >= (uint8_t)'A' && inbyte <= (uint8_t)'Z')
		return (inbyte-(uint8_t)'A');

	if (inbyte >= (uint8_t)'a' && inbyte <= (uint8_t)'z')
		return ((inbyte-(uint8_t)'a')+26);

	if (inbyte >= '0' && inbyte <= '9')
		return ((inbyte-(uint8_t)'0')+52);

	if (inbyte == (uint8_t)'+')
		return 62;

	if (inbyte == '/')
		return 63;

	return -1;
}

size_t b64_decode(const char *s, size_t nbytes, char **pdst)
{
	if (!pdst)
		return 0;

	size_t max_len = 0, bytes_left = 0;

	if (!*pdst) {
		*pdst = malloc(max_len=bytes_left=64);
		if (!*pdst) return 0;
	}

	char *dst = *pdst;
	uint8_t inbuf[4];
	int inbuf_size = 0;

	for (size_t i = 0; i < nbytes; i++) {
		int n = conv_to_number(*s++);

		if (n >= 0)
			inbuf[inbuf_size++] = (uint8_t)n;

		if (inbuf_size == 4) {
			size_t len = decode_base64(dst, inbuf, &inbuf_size);
			dst += len;
			bytes_left -= len;
		}

		if (max_len && (bytes_left < 8)) {
			max_len *= 2;
			size_t nbytes = dst - *pdst;
			bytes_left = max_len - nbytes;
			*pdst = realloc(*pdst, max_len);
			if (!*pdst) return 0;
			dst = *pdst + nbytes;
		}
	}

	if (inbuf_size) {
		for (int i = inbuf_size; i < 4; i++)
			inbuf[i] = 0;

		dst += decode_base64(dst, inbuf, &inbuf_size);
	}

	*dst = '\0';
	return dst - *pdst;
}

#endif /* USE_OPENSSL */
