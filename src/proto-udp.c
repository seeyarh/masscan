#include "proto-udp.h"
#include "proto-coap.h"
#include "proto-dns.h"
#include "proto-netbios.h"
#include "proto-snmp.h"
#include "proto-memcached.h"
#include "proto-ntp.h"
#include "proto-zeroaccess.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "logger.h"
#include "output.h"
#include "masscan-status.h"
#include "unusedparm.h"


/****************************************************************************
 * When the "--banner" command-line option is selected, this will
 * will take up to 64 bytes of a response and display it. Other UDP
 * protocol parsers may also default to this function when they detect
 * a response is not the protocol they expect. For example, if a response
 * to port 161 obviously isn't ASN.1 formatted, the SNMP parser will
 * call this function instead. In such cases, the protocool identifier will
 * be [unknown] rather than [snmp].
 ****************************************************************************/
unsigned
default_udp_parse(struct Output *out, time_t timestamp,
           const unsigned char *px, unsigned length,
           struct PreprocessedInfo *parsed,
           uint64_t entropy)
{
    ipaddress ip_them = parsed->src_ip;
    unsigned port_them = parsed->port_src;

    UNUSEDPARM(entropy);


    if (length > 2048)
        length = 2048;

    output_report_banner(
                         out, timestamp,
                         ip_them, 17, port_them,
                         PROTO_NONE,
                         parsed->ip_ttl,
                         px, length);

    return 0;
}

/****************************************************************************
 ****************************************************************************/
void
handle_udp(struct Output *out, time_t timestamp,
        const unsigned char *px, unsigned length,
        struct PreprocessedInfo *parsed, uint64_t entropy)
{
    ipaddress ip_them = parsed->src_ip;
    unsigned port_them = parsed->port_src;
    unsigned status = 0;


    switch (port_them) {
        default:
            px += parsed->app_offset;
            length = parsed->app_length;
            status = default_udp_parse(out, timestamp, px, length, parsed, entropy);
            break;
    }

    if (status == 0)
        output_report_status(
                        out,
                        timestamp,
                        PortStatus_Open,
                        ip_them,
                        17, /* ip proto = udp */
                        port_them,
                        0,
                        0,
                        parsed->mac_src);

}
