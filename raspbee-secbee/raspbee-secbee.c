#include "board.h"
#include "transceiver.h"
#include "ioutil.h"
#include "raspbee-secbee.h"
#include "hif.h"

static volatile bool tx_in_progress;
static volatile uint8_t tx_cnt, fail_cnt;
static uint8_t *txfrm;
static int framelen = 0;

#define SEQ_OFFSET     (2)
#define TX_FAIL_OFFSET (7)
#define TX_SRAM_OFFSET (1)

int readchar(void)
{
   int inchar;
   do
   {
      inchar = hif_getc();
   }
   while (EOF == inchar);
   return inchar;
}

int main(void)
{
    uint32_t panid = 0x35b6; //panid of the network
    uint32_t shortaddr = 0x0000; //shortaddr of the hub
    int channel = 20; //channel for the network

    int inchar;
    const uint32_t br = HIF_DEFAULT_BAUDRATE;
    trx_regval_t rval;

    /* This will stop the application before initializing the radio transceiver
     * (ISP issue with MISO pin, see FAQ)
     */
    trap_if_key_pressed();

    /* Step 0: init MCU peripherals */
    LED_INIT();
    trx_io_init(SPI_RATE_1_2);
    //LED_SET_VALUE(LED_MAX_VALUE);
    //LED_SET_VALUE(0);

    /* Step 1: initialize the transceiver */
    TRX_RESET_LOW();
    TRX_SLPTR_LOW();
    DELAY_US(TRX_RESET_TIME_US);
    TRX_RESET_HIGH();
    trx_reg_write(RG_TRX_STATE,CMD_TRX_OFF);
    DELAY_MS(TRX_INIT_TIME_US);
    rval = trx_bit_read(SR_TRX_STATUS);
    ERR_CHECK(TRX_OFF!=rval);
    //LED_SET_VALUE(1);

    /* Step 2: setup transmitter
     * - configure radio channel
     * - enable transmitters automatic crc16 generation
     * - go into RX state,
     * - enable "transmit end" IRQ
     */
    trx_bit_write(SR_CHANNEL,channel);
    trx_bit_write(SR_TX_AUTO_CRC_ON,1); //with crc

    /* for sending acks */
    trx_reg_write(RG_PAN_ID_0,(panid&0xff));
    trx_reg_write(RG_PAN_ID_1,(panid>>8));

    trx_reg_write(RG_SHORT_ADDR_0,(shortaddr&0xff));
    trx_reg_write(RG_SHORT_ADDR_1,(shortaddr>>8));

    trx_reg_write(RG_TRX_STATE,CMD_RX_AACK_ON);
    //trx_bit_write(SR_AACK_ACK_TIME,1); //respond with ack after 2 instead of 16 syms

#if defined(TRX_IRQ_TRX_END)
    trx_reg_write(RG_IRQ_MASK,TRX_IRQ_TRX_END);
#elif defined(TRX_IRQ_TX_END)
    trx_reg_write(RG_IRQ_MASK,TRX_IRQ_TX_END);
#else
#  error "Unknown IRQ bits"
#endif
    sei();
    //LED_SET_VALUE(2);

    /* setting up UART and adjusting the baudrate */
    hif_init(br);

    /* Step 3: wait for ans send frame (indirect data transfer) */
    tx_cnt = 0;
    tx_in_progress = false;
    //LED_SET_VALUE(0);

    uint8_t line[255];
    bool received;

    while(1)
    {
        received = false;
        while(received==false)
        {
            inchar = hif_getc();
            if (EOF != inchar)
            {
                if ((inchar =='s') && (readchar() == 'e') && (readchar() == 'c') && (readchar() == 'b') && (readchar() == 'e') && (readchar() == 'e'))
                {
                    framelen = readchar();
                    //PRINTF("Receiving frame from serial, len: %d\n\r", framelen);

                    int j;
                    for(j=0;j<framelen;j++)
                    {
                        line[j] = readchar();
                    }

                    //PRINT("Raspbee: Command queued for sending... \n\r");
                    //PRINTF("Frame as string: %s\n\r", line);
                    //LED_SET(0);
                    received = true;

                    //read PAN ID, Channel...
                    uint32_t newpanid = (uint32_t)readchar()&((uint32_t)readchar()>>8);
                    if(newpanid!=panid)
                    {
                        PRINTF("New PAN ID: %d\n\r", newpanid);
                        trx_reg_write(RG_PAN_ID_0,(panid&0xff));
                        trx_reg_write(RG_PAN_ID_1,(panid>>8));
                    }
                    uint32_t newshortaddr = (uint32_t)readchar()&((uint32_t)readchar()>>8);
                    if(newshortaddr!=shortaddr)
                    {
                        PRINTF("New Short Address: %d\n\r", newshortaddr);
                        trx_reg_write(RG_SHORT_ADDR_0,(shortaddr&0xff));
                        trx_reg_write(RG_SHORT_ADDR_1,(shortaddr>>8));
                    }
                    int newchannel = readchar();
                    if(newchannel!=channel)
                    {
                        PRINTF("New Channel: %d\n\r", newshortaddr);
                        trx_bit_write(SR_CHANNEL,channel);
                    }

                    trx_bit_write(SR_AACK_SET_PD,1);

                    int i;
                    txfrm = malloc(framelen*sizeof(uint8_t));
                    for(i=0;i<framelen;i++)
                    txfrm[i] = line[i];
                }
            }
        }

    }
}

#if defined(TRX_IF_RFA1)
ISR(TRX24_TX_END_vect)
{
    static volatile trx_regval_t trac_status;

    if (trx_bit_read(SR_AACK_SET_PD)==1)
    {
        trx_reg_write(RG_TRX_STATE,CMD_FORCE_TRX_OFF);
        trx_reg_write(RG_TRX_STATE,CMD_TX_ARET_ON);

        DELAY_US(16); /* wait 1 symbol, XXX check this timing */

        TRX_SLPTR_HIGH();
        TRX_SLPTR_LOW();

        trx_frame_write (framelen, txfrm);

        trx_bit_write(SR_AACK_SET_PD,0);

        //LED_SET(1);
        //LED_TOGGLE(0);

        trac_status = trx_bit_read(SR_TRAC_STATUS);
        tx_in_progress = false;
        if (trac_status != TRAC_SUCCESS)
        {
            fail_cnt++;
        }
        else
        {
            tx_cnt ++;
            //LED_CLR(1);
        }
  }
  else
  {
    trx_reg_write(RG_TRX_STATE,CMD_RX_AACK_ON);
  }

}
#else  /* !RFA1 */
ISR(TRX_IRQ_vect)
{
static volatile trx_regval_t irq_cause;
static volatile trx_regval_t trac_status;

    irq_cause = trx_reg_read(RG_IRQ_STATUS);
    trac_status = trx_bit_read(SR_TRAC_STATUS);

    if (irq_cause & TRX_IRQ_TRX_END)
    {
        tx_in_progress = false;
        if (trac_status != TRAC_SUCCESS)
        {
            fail_cnt++;
        }
        else
        {
            tx_cnt ++;
            //LED_CLR(1);
        }
    }
}
#endif  /* RFA1 */

/* EOF */
