#ifndef SECBEE_H
#define SECBEE_H

/* === includes ============================================================ */
#include <stdint.h>
#include <stdbool.h>
#include "board.h"
#include "ioutil.h"
#include "radio.h"
#include "transceiver.h"
/* === macros ============================================================== */
#ifndef CHANNEL
/** radio channel */
# if defined(TRX_SUPPORTS_BAND_800)
#  define CHANNEL    (0)
# elif defined(TRX_SUPPORTS_BAND_900) && defined(REGION_USA)
#  define CHANNEL    (5)
# elif defined(TRX_SUPPORTS_BAND_2400)
#  define CHANNEL    (17)
# else
#  error "No supported frequency band found"
# endif
#endif

/** Default PAN ID. */
//#define PANID      (0xcafe)
/** Default short address. */
//#define SHORT_ADDR (0xbabe)

#define ERR_CHECK(x) do{}while(x)

/* === types =============================================================== */

/* === prototypes ========================================================== */
#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif


static inline void WAIT_MS(uint16_t t)
{
    while (t--) DELAY_MS(1);
}

#define WAIT500MS() WAIT_MS(500)


static inline void ERR_CHECK_DIAG(bool test, char code)
{
uint8_t i;
    if(test)
    {
        do
        {
            LED_SET_VALUE(0);
            WAIT_MS(500);

            for(i=0;i<code;i++)
            {
                LED_SET(0);
                WAIT_MS(150);

                LED_CLR(0);
                WAIT_MS(400);
            }
            LED_SET_VALUE(0);
            WAIT_MS(500);
        }
        while(1);
    }
    LED_SET_VALUE(code);
}

#endif  /* #ifndef XMPL_H */
