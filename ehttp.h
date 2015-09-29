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
#ifndef EHTTP_VESTOL
#define EHTTP_VESTOL

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {
  EHTTP_MODE_REQUEST = 1,
  EHTTP_MODE_RESPONSE,
  EHTTP_MODE_DETECT,
} ehttp_mode;

typedef enum {
  EHTTP_PARSER_ERROR = -1,
  EHTTP_PARSER_CONTINUE = 0,
  EHTTP_PARSER_RETURN,
} ehttp_ctrl;

typedef struct _ehttp_parser ehttp_parser;
struct _ehttp_parser {
  void *context;
  /* parser state */
  const uint8_t *p;
  const uint8_t *end;
  const uint8_t *mark;
  uint8_t state;
  /* http info */
  uint8_t majorVersion;
  uint8_t minorVersion;
  uint16_t statusCode;
  ehttp_mode mode;
  uint8_t requestType;
  uint8_t hasContent;
  uint8_t isChunked;
  uint8_t isUpgrade;
  uint8_t shouldClose;
  uint8_t haveHostHeader;
  size_t contentLength;
  // sub states
  uint8_t hnstate;
  uint8_t hvstate;
};

typedef struct _ehttp_callbacks ehttp_callbacks;
struct _ehttp_callbacks {
        void (*on_method)(ehttp_parser *, const uint8_t *, size_t);
  ehttp_ctrl (*on_method_done)(ehttp_parser *);
        void (*on_request_uri)(ehttp_parser *, const uint8_t *, size_t);
  ehttp_ctrl (*on_request_uri_done)(ehttp_parser *);
  ehttp_ctrl (*on_status_line_done)(ehttp_parser *);
        void (*on_header_name)(ehttp_parser *, const uint8_t *, size_t);
  ehttp_ctrl (*on_header_name_done)(ehttp_parser *);
        void (*on_header_value)(ehttp_parser *, const uint8_t *, size_t);
  ehttp_ctrl (*on_header_value_done)(ehttp_parser *);
  ehttp_ctrl (*on_headers_done)(ehttp_parser *);
        void (*on_content)(ehttp_parser *, const uint8_t *, size_t);
  ehttp_ctrl (*on_parser_done)(ehttp_parser *);
  ehttp_ctrl (*on_error)(ehttp_parser *);
};

#ifndef EVERSION_VESTOL
typedef struct {
  unsigned char major;
  unsigned char minor;
  unsigned char patch;
} eversion;
#endif

const eversion *ehhtp_version(void);

/**
 *
 */
ehttp_parser *ehttp_init(ehttp_parser * const restrict,
                         ehttp_mode, void * const restrict);

/**
 *
 */
int ehttp_parse(ehttp_parser * const restrict,
                const void * const restrict, size_t,
                const ehttp_callbacks * const restrict);

/**
 *
 */
ehttp_parser *ehttp_reset(ehttp_parser * const restrict, void * const restrict);

/**
 * Sets empty default handlers for callbacks.
 */
ehttp_callbacks *ehttp_defaults(ehttp_callbacks * const);

#endif
