/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */
#include "ehttp.h"

enum ihttp_states {
  // undetermined
  S_NOSTATE = 0,
  S_UND_H,
  S_UND_HT,
  S_UND_HTT,
  S_UND_HTTP,

  S_REQUEST_REQUIRED,
  S_METHOD_CHAR,

  S_REQUEST_URI,
  S_REQUEST_URI_CHAR,
  S_REQUEST_URI_ASTERISK,

  S_REQUEST_URI_1ST_HEX,
  S_REQUEST_URI_2ND_HEX,

  S_REQUEST_REQUIRE_VERSION,
  S_REQUEST_H,
  S_REQUEST_HT,
  S_REQUEST_HTT,
  S_REQUEST_HTTP,
  S_REQUEST_HTTP_MAJORV,
  S_REQUEST_HTTP_DOT,
  S_REQUEST_HTTP_MINORV,

  S_REQUEST_EOL,
  S_REQUEST_CRLF,

 /*
  * Http response states
  */
  S_RESPONSE_REQUIRED,

  S_RESPONSE_H,
  S_RESPONSE_HT,
  S_RESPONSE_HTT,
  S_RESPONSE_HTTP,
  S_RESPONSE_HTTP_SLASH,

  S_RESPONSE_HTTP_MAJORV,
  S_RESPONSE_HTTP_DOT,
  S_RESPONSE_HTTP_MINORV,

  S_STATUS_REQUIRED,
  S_STATUS_1ST,
  S_STATUS_2ND,
  S_STATUS_3RD,

  S_RESPONSE_REASON,
  S_RESPONSE_EOL,

 /*
  * Http headers
  */
  S_HEADER_NAME,
  S_HEADER_NAME_CHAR,
  S_HEADER_NAME_CHAR_CHECK,

  S_HEADER_VALUE,
  S_HEADER_VALUE_CHAR,

  S_HEADER_VALUE_LF_CLOSE,
  S_HEADER_VALUE_LF_CHUNKED,
  S_HEADER_VALUE_LF_CHUNKED_CHAR,

  S_HEADER_VALUE_CONTENT_LENGTH,
  S_HEADER_VALUE_END_TRIM,

  S_HEADER_EOL,
  S_HEADER_CRLF,

 /*
  * Last CRLF (end of headers)
  */
  S_HEADER_EOH,
  S_HEADERS_DONE,

 /*
  * Content body
  */
  S_BODY_CONTENT_LENGHT,

  S_BODY_CHUNKED,
  S_BODY_CHUNKLEN,
  S_BODY_CHUNKLEN_CRLF,

  S_BODY_CHUNK,
  S_BODY_CHUNK_CR,
  S_BODY_CHUNK_CRLF,

  S_BODY_CHUNKED_EOS,

  S_STATE_END,
};


// header names
enum {
  SH_IGNORE = 0,
  SH_NOSTATE,

  SH_C, SH_CO, SH_CON, SH_CONN, SH_CONNE, SH_CONNEC, SH_CONNECT, SH_CONNECTI,
  SH_CONNECTIO, SH_CONNECTION,

  SH_CONT, SH_CONTE, SH_CONTEN, SH_CONTENT, SH_CONTENT_, SH_CONTENT_L,
  SH_CONTENT_LE, SH_CONTENT_LEN, SH_CONTENT_LENG, SH_CONTENT_LENGT,
  SH_CONTENT_LENGTH,

  SH_H, SH_HO, SH_HOS, SH_HOST,

  SH_T, SH_TR, SH_TRA, SH_TRAN, SH_TRANS, SH_TRANSF, SH_TRANSFE, SH_TRANSFER,
  SH_TRANSFER_, SH_TRANSFER_E, SH_TRANSFER_EN, SH_TRANSFER_ENC, SH_TRANSFER_ENCO,
  SH_TRANSFER_ENCOD, SH_TRANSFER_ENCODI, SH_TRANSFER_ENCODIN,
  SH_TRANSFER_ENCODING,

  SH_U, SH_UP, SH_UPG, SH_UPGR, SH_UPGRA, SH_UPGRAD, SH_UPGRADE,

  SH_STATE_MAX,
};

enum {
  SCLOSE_NOSTATE = 0,
  SCLOSE_WAIT,
  SCLOSE_C,
  SCLOSE_CL,
  SCLOSE_CLO,
  SCLOSE_CLOS,
  SCLOSE_CLOSE,

  SCLOSE_CONFIRMED
};

enum {
  SCHUNKED_WAIT = 0,
  SCHUNKED_TRIM,
  SCHUNKED_NOSTATE,
  SCHUNKED_C,
  SCHUNKED_CH,
  SCHUNKED_CHU,
  SCHUNKED_CHUN,
  SCHUNKED_CHUNK,
  SCHUNKED_CHUNKE,
  SCHUNKED_CHUNKED,
  SCHUNKED_CONFIRMED,

  SCHUNKED_ILLEGAL,
};

/**
 * @bug Requires at least one header
 */

static const uint8_t token[0x100];
static const uint8_t vchar[0x100];
static const uint8_t urichar[0x100];
static const uint8_t hexchar[0x100];

static uint8_t header_name_lookup(uint8_t state, uint8_t c);
static uint8_t header_lf_close(uint8_t state, uint8_t c);
static uint8_t header_lf_chunked(uint8_t state, uint8_t c);


const eversion *ehhtp_version(void) {
  static const eversion version = { .minor = 1 };
  return &version;
}

/**
 *
 */
ehttp_parser *ehttp_init(ehttp_parser * const restrict out,
                         ehttp_mode mode, void * const restrict ctx) {
#ifdef CORE_HTTP_CHECKS
  if (!out || mode < 1 || mode > 3) {
    return -1;
  }
#endif
  *out = (ehttp_parser) {
    .mode = mode,
    .context = ctx,
  };

  if (out->mode == EHTTP_MODE_REQUEST)
    out->state = S_REQUEST_REQUIRED;
  else if (out->mode == EHTTP_MODE_RESPONSE)
    out->state = S_RESPONSE_REQUIRED;

  return 0;
}

/**
 *
 */
ehttp_parser *ehttp_reset(ehttp_parser * const restrict out,
                          void * const restrict ctx) {
  return ehttp_init(out, out->mode, ctx);
}

/**
 * Sets empty default handlers for callbacks.
 */
ehttp_callbacks *ehttp_defaults(ehttp_callbacks * const out) {
  *out = (ehttp_callbacks) {
    .on_error = NULL
  };

  return out;
}


int ehttp_parse(ehttp_parser * const restrict s,
                  const void * restrict in, size_t size,
                  const ehttp_callbacks * const restrict callbacks)
{
  ehttp_ctrl ctrl;

#ifdef CORE_HTTP_CHECKS
  if (!s || !in || !size || !callbacks || s->mode < EHTTP_MODE_REQUEST || s->mode > EHTTP_MODE_RESPONSE) {
    return -1;
  }
#endif

  s->end = (const uint8_t *) in + size;
  s->mark = in;
  s->p = in;

  for (; s->p < s->end; s->p++) {
    size_t tmp;
check_again:
    switch (s->state) {
      case S_NOSTATE:
        s->mark = s->p;
        if (*s->p == 'H') {
          s->state = S_UND_H;
          continue;
        }
        else if (token[*s->p]) {
          s->requestType = EHTTP_MODE_REQUEST;
          s->state = S_METHOD_CHAR;
          continue;
        }

        break;

      case S_UND_H:
        if (*s->p == 'T') {
          s->state = S_UND_HT;
          continue;
        }
        else if (token[*s->p]) {
          s->requestType = EHTTP_MODE_REQUEST;
          s->state = S_METHOD_CHAR;
          continue;
        }

        break;

      case S_UND_HT:
        if (*s->p == 'T') {
          s->state = S_UND_HTT;
          continue;
        }
        else if (token[*s->p]) {
          s->requestType = EHTTP_MODE_REQUEST;
          s->state = S_METHOD_CHAR;
          continue;
        }

        break;

      case S_UND_HTT:
        if (*s->p == 'P') {
          s->state = S_UND_HTTP;
          continue;
        }
        else if (token[*s->p]) {
          s->requestType = EHTTP_MODE_REQUEST;
          s->state = S_METHOD_CHAR;
          continue;
        }

        break;

      case S_UND_HTTP:
        if (*s->p == '/') {
          s->state = S_RESPONSE_HTTP_MAJORV;
          s->requestType = EHTTP_MODE_RESPONSE;
          continue;
        }
        else if (token[*s->p]) {
          s->requestType = EHTTP_MODE_REQUEST;
          s->state = S_METHOD_CHAR;
          continue;
        }

        break;

      case S_REQUEST_REQUIRED:
        s->mark = s->p;
        if (token[*s->p]) {
          s->state = S_METHOD_CHAR;
          continue;
        }

        break;

      case S_METHOD_CHAR:
        if (token[*s->p]) {
          continue;
        }
        else if (*s->p == ' ') {
          callbacks->on_method(s, s->mark, s->p - s->mark);
          s->state = S_REQUEST_URI;
          if ( (ctrl = callbacks->on_method_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_REQUEST_URI:
        // legal chars at 1st
        s->mark = s->p;
        if (*s->p == '/' || *s->p == 'h' || *s->p == 'H') {
          s->state = S_REQUEST_URI_CHAR;
          continue;
        }
        else if (*s->p == '*') {
          s->state = S_REQUEST_URI_ASTERISK;
          continue;
        }

        break;

      case S_REQUEST_URI_CHAR:
        if (urichar[*s->p]) {
          continue;
        }
        else if (*s->p == '%') {
          s->state = S_REQUEST_URI_1ST_HEX;
          continue;
        }
        else if (*s->p == ' ') {
          callbacks->on_request_uri(s, s->mark, s->p - s->mark);
          s->state = S_REQUEST_REQUIRE_VERSION;
          if ( (ctrl = callbacks->on_request_uri_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_REQUEST_URI_1ST_HEX:
        if (hexchar[*s->p]) {
          s->state = S_REQUEST_URI_2ND_HEX;
          continue;
        }

        break;

      case S_REQUEST_URI_2ND_HEX:
        if (hexchar[*s->p]) {
          s->state = S_REQUEST_URI_CHAR;
          continue;
        }

        break;

      case S_REQUEST_URI_ASTERISK:
        if (*s->p == ' ') {
          s->state = S_REQUEST_REQUIRE_VERSION;
          continue;
        }

        break;

      case S_REQUEST_REQUIRE_VERSION:
        if (*s->p == 'H') {
          s->state = S_REQUEST_H;
          continue;
        }

        break;

      case S_REQUEST_H:
        if (*s->p == 'T') {
          s->state = S_REQUEST_HT;
          continue;
        }

        break;

      case S_REQUEST_HT:
        if (*s->p == 'T') {
          s->state = S_REQUEST_HTT;
          continue;
        }

        break;

      case S_REQUEST_HTT:
        if (*s->p == 'P') {
          s->state = S_REQUEST_HTTP;
          continue;
        }

        break;

      case S_REQUEST_HTTP:
        if (*s->p == '/') {
          s->state = S_REQUEST_HTTP_MAJORV;
          continue;
        }

        break;

      case S_REQUEST_HTTP_MAJORV:
        if (*s->p >= '0' && *s->p <= '9') {
          s->majorVersion = *s->p - '0';
          s->state = S_REQUEST_HTTP_DOT;
          continue;
        }

        break;

      case S_REQUEST_HTTP_DOT:
        if (*s->p == '.') {
          s->state = S_REQUEST_HTTP_MINORV;
          continue;
        }

        break;

      case S_REQUEST_HTTP_MINORV:
        if (*s->p >= '0' && *s->p <= '9') {
          s->minorVersion = *s->p - '0';
          s->state = S_REQUEST_EOL;
          continue;
        }

        break;

      case S_REQUEST_EOL:
        if (*s->p == '\r') {
          s->state = S_REQUEST_CRLF;
          continue;
        }

        break;

      case S_REQUEST_CRLF:
        if (*s->p == '\n') {
          s->state = S_HEADER_NAME;
          if ( (ctrl = callbacks->on_status_line_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_RESPONSE_REQUIRED:
        if (*s->p == 'H') {
          s->state = S_RESPONSE_H;
          continue;
        }

        break;

      case S_RESPONSE_H:
        if (*s->p == 'T') {
          s->state = S_RESPONSE_HT;
          continue;
        }

        break;

      case S_RESPONSE_HT:
        if (*s->p == 'T') {
          s->state = S_RESPONSE_HTT;
          continue;
        }

        break;

      case S_RESPONSE_HTT:
        if (*s->p == 'P') {
          s->state = S_RESPONSE_HTTP;
          continue;
        }

        break;

      case S_RESPONSE_HTTP:
        if (*s->p == '/') {
          s->state = S_RESPONSE_HTTP_MAJORV;
          continue;
        }

        break;

      case S_RESPONSE_HTTP_MAJORV:
        if (*s->p >= '0' && *s->p <= '9') {
          s->majorVersion = *s->p - '0';
          s->state = S_RESPONSE_HTTP_DOT;
          continue;
        }

        break;

      case S_RESPONSE_HTTP_DOT:
        if (*s->p == '.') {
          s->state = S_RESPONSE_HTTP_MINORV;
          continue;
        }

        break;

      case S_RESPONSE_HTTP_MINORV:
        if (*s->p >= '0' && *s->p <= '9') {
          s->minorVersion = *s->p - '0';
          s->state = S_STATUS_REQUIRED;
          continue;
        }

        break;

      case S_STATUS_REQUIRED:
        if (*s->p == ' ') {
          s->state = S_STATUS_1ST;
          continue;
        }

        break;

      case S_STATUS_1ST:
        if (*s->p >= '1' && *s->p <= '9') {
          s->statusCode = (*s->p - '0') * 100;
          s->state = S_STATUS_2ND;
          continue;
        }

        break;

      case S_STATUS_2ND:
        if (*s->p >= '0' && *s->p <= '9') {
          s->statusCode += (*s->p - '0') * 10;
          s->state = S_STATUS_3RD;
          continue;
        }

        break;

      case S_STATUS_3RD:
        if (*s->p >= '0' && *s->p <= '9') {
          s->statusCode += (*s->p - '0');
          s->state = S_RESPONSE_REASON;
          continue;
        }

        break;

      case S_RESPONSE_REASON:
        if (vchar[*s->p]) {
          continue;
        }
        else if (*s->p == '\r') {
          s->state = S_RESPONSE_EOL;
          continue;
        }

        break;

      case S_RESPONSE_EOL:
        if (*s->p == '\n') {
          s->state = S_HEADER_NAME;
          if ( (ctrl = callbacks->on_status_line_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_HEADER_NAME:
        s->mark = s->p;
        if (token[*s->p]) {
          if ( (s->hnstate = header_name_lookup(SH_NOSTATE, *s->p) ) == 0) {
            s->state = S_HEADER_NAME_CHAR;
          }
          else {
            s->state = S_HEADER_NAME_CHAR_CHECK;
          }
          continue;
        }
        // no headers
        else if (*s->p == '\r') {
          s->state = S_HEADER_EOH;
          continue;
        }

        break;

      case S_HEADER_NAME_CHAR:
        if (token[*s->p]) {
          continue;
        }
        else if (*s->p == ':') {
          callbacks->on_header_name(s, s->mark, s->p - s->mark);
          s->state = S_HEADER_VALUE;
          if ( (ctrl = callbacks->on_header_name_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_HEADER_NAME_CHAR_CHECK:
        if (token[*s->p]) {
          if ( (s->hnstate = header_name_lookup(s->hnstate, *s->p) ) == 0) {
            s->state = S_HEADER_NAME_CHAR;
          }

          continue;
        }
        else if (*s->p == ':') {
          callbacks->on_header_name(s, s->mark, s->p - s->mark);
          s->state = S_HEADER_VALUE;
          if ( (ctrl = callbacks->on_header_name_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_HEADER_VALUE:
        // trim ows
        if (*s->p == ' ' || *s->p == '\t') {
          continue;
        }
        else if (vchar[*s->p]) {
          s->mark = s->p;

          switch (s->hnstate) {
            case SH_CONNECTION:
              s->state = S_HEADER_VALUE_LF_CLOSE;
              goto check_again;

            case SH_HOST:
              s->state = S_HEADER_VALUE_CHAR;
              s->haveHostHeader = 1;
              goto check_again;

            case SH_TRANSFER_ENCODING:
              s->state = S_HEADER_VALUE_LF_CHUNKED;
              goto check_again;

            case SH_CONTENT_LENGTH:
              if (s->contentLength) {
                break;
              }

              s->state = S_HEADER_VALUE_CONTENT_LENGTH;
              goto check_again;

            case SH_UPGRADE:
              s->state = S_HEADER_VALUE_CHAR;
              s->isUpgrade = 1;
              goto check_again;

            default:
              s->state = S_HEADER_VALUE_CHAR;
              goto check_again;
          }
        }

        break;

      case S_HEADER_VALUE_CHAR:
        if (vchar[*s->p]) {
          continue;
        }
        else if (*s->p == '\r') {
          callbacks->on_header_value(s, s->mark, s->p - s->mark);
          s->state = S_HEADER_EOL;
          if ( (ctrl = callbacks->on_header_value_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_HEADER_VALUE_LF_CLOSE:
        if (vchar[*s->p]) {
          s->hvstate = header_lf_close(s->hvstate, *s->p);
          continue;
        }
        else if (*s->p == '\r') {
          s->hvstate = header_lf_close(s->hvstate, *s->p);

          if (s->hvstate == SCLOSE_CONFIRMED) {
            s->shouldClose = 1;
          }

          callbacks->on_header_value(s, s->mark, s->p - s->mark);
          s->state = S_HEADER_EOL;
          if ( (ctrl = callbacks->on_header_value_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_HEADER_VALUE_LF_CHUNKED:
        if (vchar[*s->p]) {
          s->hvstate = header_lf_chunked(SCHUNKED_NOSTATE, *s->p);
          s->state = S_HEADER_VALUE_LF_CHUNKED_CHAR;
          continue;
        }

        break;

      case S_HEADER_VALUE_LF_CHUNKED_CHAR:
        if (vchar[*s->p]) {
          s->hvstate = header_lf_chunked(s->hvstate, *s->p);
          continue;
        }
        else if (*s->p == '\r') {
          s->hvstate = header_lf_chunked(s->hvstate, *s->p);
          if (s->hvstate == SCHUNKED_CONFIRMED) {
            s->isChunked = 1;
          }

          callbacks->on_header_value(s, s->mark, s->p - s->mark);
          s->state = S_HEADER_EOL;
          if ( (ctrl = callbacks->on_header_value_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_HEADER_VALUE_CONTENT_LENGTH:
        if (*s->p >= '0' && *s->p <= '9') {
          s->contentLength *= 10;
          s->contentLength += (*s->p - '0');
          continue;
        }
        else if (*s->p == ' ' || *s->p == '\t') {
          callbacks->on_header_value(s, s->mark, s->p - s->mark);
          s->state = S_HEADER_VALUE_END_TRIM;
          if ( (ctrl = callbacks->on_header_value_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }
        else if (*s->p == '\r') {
          callbacks->on_header_value(s, s->mark, s->p - s->mark);
          s->state = S_HEADER_EOL;
          if ( (ctrl = callbacks->on_header_value_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_HEADER_VALUE_END_TRIM:
        if (*s->p == ' ' || *s->p == '\t') {
          continue;
        }
        else if (*s->p == '\r') {
          s->state = S_HEADER_EOL;
          continue;
        }

        break;

      case S_HEADER_EOL:
        if (*s->p == '\n') {
          s->state = S_HEADER_CRLF;
          continue;
        }

        break;

      case S_HEADER_CRLF:
        if (*s->p == '\r') {
          s->state = S_HEADER_EOH;
          continue;
        }

        else if (token[*s->p]) {
          s->state = S_HEADER_NAME;
          goto check_again;
        }

        break;

      case S_HEADER_EOH:
        if (*s->p == '\n') {
          s->state = S_HEADERS_DONE;

          // prepare state for headers done

          if (s->contentLength && !s->isChunked) {
            s->hasContent = 1;
          }

          else if (s->isChunked && !s->contentLength) {
            s->hasContent = 1;
          }

          if (!s->hasContent && (s->contentLength || s->isChunked) ) {
            // ambigous transfer encoding
            break;
          }

          if (s->contentLength) {
            s->state = S_BODY_CONTENT_LENGHT;
            if ( (ctrl = callbacks->on_headers_done(s) ) != EHTTP_PARSER_CONTINUE) {
              goto early_return;
            }
            continue;
          }
          else if (s->isChunked) {
            s->state = S_BODY_CHUNKED;
            if ( (ctrl = callbacks->on_headers_done(s) ) != EHTTP_PARSER_CONTINUE) {
              goto early_return;
            }
            continue;
          }

          if ( (ctrl = callbacks->on_headers_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }

          s->state = S_STATE_END;
          if ( (ctrl = callbacks->on_parser_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_BODY_CONTENT_LENGHT:
        s->mark = s->p;
        tmp = size - (s->mark - (const uint8_t *) in);

        if (s->contentLength > tmp) {
          callbacks->on_content(s, s->mark, tmp);
          s->contentLength -= tmp;
          s->p += tmp - 1;
          continue;
        }
        else {
          callbacks->on_content(s, s->mark, s->contentLength);
          s->contentLength = 0;
          if ( (ctrl = callbacks->on_parser_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          return 0;
        }

        break;

      case S_BODY_CHUNKED:
        if (*s->p >= '0' && *s->p <= '9') {
          s->contentLength = *s->p - '0';
          s->state = S_BODY_CHUNKLEN;
          continue;
        }
        else if (*s->p >= 'a' && *s->p <= 'f') {
          s->contentLength = (*s->p - 'a') + 10;
          s->state = S_BODY_CHUNKLEN;
          continue;
        }
        else if (*s->p >= 'A' && *s->p <= 'F') {
          s->contentLength = (*s->p - 'A') + 10;
          s->state = S_BODY_CHUNKLEN;
          continue;
        }

        break;

      case S_BODY_CHUNKLEN:
        if (*s->p >= '0' && *s->p <= '9') {
          s->contentLength = s->contentLength << 4;
          s->contentLength += *s->p - '0';
          continue;
        }
        else if (*s->p >= 'a' && *s->p <= 'f') {
          s->contentLength = s->contentLength << 4;
          s->contentLength += (*s->p - 'a') + 10;
          continue;
        }
        else if (*s->p >= 'A' && *s->p <= 'F') {
          s->contentLength = s->contentLength << 4;
          s->contentLength += (*s->p - 'A') + 10;
          continue;
        }

        else if (*s->p == '\r') {
          if (s->contentLength == 0) {
            s->state = S_BODY_CHUNKED_EOS;
            continue;
          }

          s->state = S_BODY_CHUNKLEN_CRLF;
          continue;
        }

        break;

      case S_BODY_CHUNKLEN_CRLF:
        if (*s->p == '\n') {
          s->state = S_BODY_CHUNK;
          continue;
        }

        break;

      case S_BODY_CHUNK:
        s->mark = s->p;
        tmp = size - (s->mark - (const uint8_t *) in);

        if (s->contentLength >= tmp) {
          s->p += tmp - 1;
          callbacks->on_content(s, s->mark, tmp);
          s->contentLength -= tmp;
          continue;
        }

        callbacks->on_content(s, s->mark, s->contentLength);
        s->p += s->contentLength - 1;
        s->contentLength = 0;
        s->state = S_BODY_CHUNK_CR;
        continue;

      // require \r after chunk
      case S_BODY_CHUNK_CR:
        if (*s->p == '\r') {
          s->state = S_BODY_CHUNK_CRLF;
          continue;
        }

        break;

      case S_BODY_CHUNK_CRLF:
        if (*s->p == '\n') {
          s->state = S_BODY_CHUNKED;
          continue;
        }

        break;

      case S_BODY_CHUNKED_EOS:
        if (*s->p == '\n') {
          s->state = S_STATE_END;
          if ( (ctrl = callbacks->on_parser_done(s) ) != EHTTP_PARSER_CONTINUE) {
            goto early_return;
          }
          continue;
        }

        break;

      case S_STATE_END:
        return size - (s->p - (uint8_t *) in);
    }

    callbacks->on_error(s);
    return -1;
  }

  if (s->state == S_METHOD_CHAR)
    callbacks->on_method(s, s->mark, s->p - s->mark);
  else if (s->state > S_REQUEST_URI && s->state < S_REQUEST_REQUIRE_VERSION)
    callbacks->on_request_uri(s, s->mark, s->p - s->mark);
  else if (s->state >= S_HEADER_NAME && s->state < S_HEADER_VALUE)
    callbacks->on_header_name(s, s->mark, s->p - s->mark);
  else if (s->state >= S_HEADER_VALUE && s->state < S_HEADER_EOL)
    callbacks->on_header_value(s, s->mark, s->p - s->mark);

  return 0;

early_return:
  if (ctrl == EHTTP_PARSER_RETURN)
    return size - (s->p - (uint8_t *) in);

  return 1;
}

static uint8_t header_name_lookup(uint8_t state, uint8_t c) {
  static const uint8_t table[][0x100] = {
    [SH_NOSTATE] = {
      ['C'] = SH_C, ['H'] = SH_H, ['T'] = SH_T, ['U'] = SH_U,
      ['c'] = SH_C, ['h'] = SH_H, ['t'] = SH_T, ['u'] = SH_U,
    },
    [SH_C] = { ['O'] = SH_CO, ['o'] = SH_CO },
    [SH_CO] = { ['N'] = SH_CON, ['n'] = SH_CON },
    [SH_CON] = {
      ['N'] = SH_CONN, ['T'] = SH_CONT,
      ['n'] = SH_CONN, ['t'] = SH_CONT,
    },
    [SH_CONN] = { ['E'] = SH_CONNE, ['e'] = SH_CONNE },
    [SH_CONNE] = { ['C'] = SH_CONNEC, ['c'] = SH_CONNEC },
    [SH_CONNEC] = { ['T'] = SH_CONNECT, ['t'] = SH_CONNECT },
    [SH_CONNECT] = { ['I'] = SH_CONNECTI, ['i'] = SH_CONNECTI },
    [SH_CONNECTI] = { ['O'] = SH_CONNECTIO, ['o'] = SH_CONNECTIO },
    [SH_CONNECTIO] = { ['N'] = SH_CONNECTION, ['n'] = SH_CONNECTION },

    [SH_CONT] = { ['E'] = SH_CONTE, ['e'] = SH_CONTE },
    [SH_CONTE] = { ['N'] = SH_CONTEN, ['n'] = SH_CONTEN },
    [SH_CONTEN] = { ['T'] = SH_CONTENT, ['t'] = SH_CONTENT },
    [SH_CONTENT] = { ['-'] = SH_CONTENT_ },
    [SH_CONTENT_] = { ['L'] = SH_CONTENT_L, ['l'] = SH_CONTENT_L },
    [SH_CONTENT_L] = { ['E'] = SH_CONTENT_LE, ['e'] = SH_CONTENT_LE },
    [SH_CONTENT_LE] = { ['N'] = SH_CONTENT_LEN, ['n'] = SH_CONTENT_LEN },
    [SH_CONTENT_LEN] = { ['G'] = SH_CONTENT_LENG, ['g'] = SH_CONTENT_LENG },
    [SH_CONTENT_LENG] = { ['T'] = SH_CONTENT_LENGT, ['t'] = SH_CONTENT_LENGT },
    [SH_CONTENT_LENGT] = {
      ['H'] = SH_CONTENT_LENGTH, ['h'] = SH_CONTENT_LENGTH
    },

    [SH_H] = { ['O'] = SH_HO, ['o'] = SH_HO },
    [SH_HO] = { ['S'] = SH_HOS, ['s'] = SH_HOS },
    [SH_HOS] = { ['T'] = SH_HOST, ['t'] = SH_HOST },

    [SH_T] = { ['R'] = SH_TR, ['r'] = SH_TR },
    [SH_TR] = { ['A'] = SH_TRA, ['a'] = SH_TRA},
    [SH_TRA] = { ['N'] = SH_TRAN, ['n'] = SH_TRAN},
    [SH_TRAN] = { ['S'] = SH_TRANS, ['s'] = SH_TRANS },
    [SH_TRANS] = { ['F'] = SH_TRANSF, ['f'] = SH_TRANSF },
    [SH_TRANSF] = { ['E'] = SH_TRANSFE, ['e'] = SH_TRANSFE },
    [SH_TRANSFE] = { ['R'] = SH_TRANSFER, ['r'] = SH_TRANSFER },
    [SH_TRANSFER] = { ['-'] = SH_TRANSFER_ },
    [SH_TRANSFER_] = { ['E'] = SH_TRANSFER_E, ['e'] = SH_TRANSFER_E },
    [SH_TRANSFER_E] = { ['N'] = SH_TRANSFER_EN, ['n'] = SH_TRANSFER_EN },
    [SH_TRANSFER_EN] = { ['C'] = SH_TRANSFER_ENC, ['c'] = SH_TRANSFER_ENC },
    [SH_TRANSFER_ENC] = { ['O'] = SH_TRANSFER_ENCO, ['o'] = SH_TRANSFER_ENCO },
    [SH_TRANSFER_ENCO] = {
      ['D'] = SH_TRANSFER_ENCOD, ['d'] = SH_TRANSFER_ENCOD
    },
    [SH_TRANSFER_ENCOD] = {
      ['I'] = SH_TRANSFER_ENCODI, ['i'] = SH_TRANSFER_ENCODI
    },
    [SH_TRANSFER_ENCODI] = {
      ['N'] = SH_TRANSFER_ENCODIN, ['n'] = SH_TRANSFER_ENCODIN
    },
    [SH_TRANSFER_ENCODIN] = {
      ['G'] = SH_TRANSFER_ENCODING, ['g'] = SH_TRANSFER_ENCODING
    },

    [SH_U] = { ['P'] = SH_UP, ['p'] = SH_UP },
    [SH_UP] = { ['G'] = SH_UPG, ['g'] = SH_UPG },
    [SH_UPG] = { ['R'] = SH_UPGR, ['r'] = SH_UPGR },
    [SH_UPGR] = { ['A'] = SH_UPGRA, ['a'] = SH_UPGRA },
    [SH_UPGRA] = { ['D'] = SH_UPGRAD, ['d'] = SH_UPGRAD },
    [SH_UPGRAD] = { ['E'] = SH_UPGRADE, ['e'] = SH_UPGRADE },
  };

  return table[state][c];
}

// looking for "close" token
static uint8_t header_lf_close(uint8_t state, uint8_t c) {
  switch (state) {
    case SCLOSE_NOSTATE:
      if (c == 'C' || c == 'c') {
        return SCLOSE_C;
      }
      else if (c == ',' || c == ' ' || c == '\t') {
        return SCLOSE_NOSTATE;
      }

      return SCLOSE_WAIT;

    // wait for ,
    case SCLOSE_WAIT:
      if (c == ',') {
        return SCLOSE_NOSTATE;
      }

      return SCLOSE_WAIT;

    case SCLOSE_C:
      if (c == 'L' || c == 'l') {
        return SCLOSE_CL;
      }

      return SCLOSE_WAIT;

    case SCLOSE_CL:
      if (c == 'O' || c == 'o') {
        return SCLOSE_CLO;
      }

      return SCLOSE_WAIT;

    case SCLOSE_CLO:
      if (c == 'S' || c == 's') {
        return SCLOSE_CLOS;
      }

      return SCLOSE_WAIT;

    case SCLOSE_CLOS:
      if (c == 'E' || c == 'e') {
        return SCLOSE_CLOSE;
      }

      return SCLOSE_WAIT;

    case SCLOSE_CLOSE:
      if (c == ' ' || c == '\t' || c == '\t' || c == '\r' || c == ',') {
        return SCLOSE_CONFIRMED;
      }

      return SCLOSE_WAIT;

    case SCLOSE_CONFIRMED:
      return SCLOSE_CONFIRMED;
  }

  return 0;
}

// looking for "chunked" token (must be the last one)
static uint8_t header_lf_chunked(uint8_t state, uint8_t c) {
  //fprintf(stderr, "%s %u:%c\n", __func__, state, c);
  const uint8_t table[][0x100] = {
    [SCHUNKED_WAIT] = {
      [','] = SCHUNKED_TRIM
    },
    [SCHUNKED_TRIM] = {
      [' '] = SCHUNKED_TRIM, ['\t'] = SCHUNKED_TRIM,
      ['C'] = SCHUNKED_C, ['c'] = SCHUNKED_C,
    },

    [SCHUNKED_NOSTATE] = { ['C'] = SCHUNKED_C, ['c'] = SCHUNKED_C },
    [SCHUNKED_C] = { ['H'] = SCHUNKED_CH, ['h'] = SCHUNKED_CH },
    [SCHUNKED_CH] = { ['U'] = SCHUNKED_CHU, ['u'] = SCHUNKED_CHU },
    [SCHUNKED_CHU] = { ['N'] = SCHUNKED_CHUN, ['n'] = SCHUNKED_CHUN },
    [SCHUNKED_CHUN] = { ['K'] = SCHUNKED_CHUNK, ['k'] = SCHUNKED_CHUNK },
    [SCHUNKED_CHUNK] = { ['E'] = SCHUNKED_CHUNKE, ['e'] = SCHUNKED_CHUNKE },
    [SCHUNKED_CHUNKE] = { ['D'] = SCHUNKED_CHUNKED, ['d'] = SCHUNKED_CHUNKED },
    [SCHUNKED_CHUNKED] = {
      // QWS at the end
      [' '] = SCHUNKED_CHUNKED,
      ['\t'] = SCHUNKED_CHUNKED,
      ['\r'] = SCHUNKED_CONFIRMED,
      // chunk not last
      [','] = SCHUNKED_ILLEGAL,
    },
  };
  if (state == SCHUNKED_ILLEGAL) {
    return SCHUNKED_ILLEGAL;
  }
  return (state == SCHUNKED_CONFIRMED) ? SCHUNKED_CONFIRMED : table[state][c];
}

static const uint8_t token[0x100] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
};

static const uint8_t vchar[0x100] = {
  ['\t'] = 1,
  [' '] = 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
#ifndef CORE_HTTP_STRICT
 [0x80] = 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
#endif
};

static const uint8_t urichar[0x100] = {
  ['-'] = 1, ['.'] = 1, ['_'] = 1, ['~'] = 1, [':'] = 1, ['/'] = 1,
  ['?'] = 1, ['#'] = 1, ['['] = 1, [']'] = 1, ['@'] = 1, ['!'] = 1,
  ['$'] = 1, ['&'] = 1, ['\''] = 1, ['('] = 1, [')'] = 1, ['*'] = 1,
  ['+'] = 1, [','] = 1, [';'] = 1, ['='] = 1,
  ['0'] = 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  ['A'] = 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  ['a'] = 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

static const uint8_t hexchar[0x100] = {
  ['0'] = 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  ['A'] = 1, 1, 1, 1, 1, 1,
  ['a'] = 1, 1, 1, 1, 1, 1,
};
