/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */
#ifndef BGPPREFIXSID_H_
#define BGPPREFIXSID_H_

#include "bgp_common.h"
#include "Logger.h"
#include <list>
#include <string>
#include <boost/property_tree/ptree.hpp>

#include "UpdateMsg.h"

namespace bgp_msg {

/**
 * \class   BGPPrefixSID
 *
 * \brief   BGP Prefix-SID attribute parser
 * \details This class parses BGP Prefix-SID attributes.
 *          It can be extended to create attributes messages.
 */
class BGPPrefixSID {
public:

    enum BGP_PREFIX_SID_TLV_TYPES {
        BGP_PREFIX_SID_TLV_TYPE_LABEL_INDEX = 1,
        BGP_PREFIX_SID_TLV_TYPE_DEPRECATED_2,
        BGP_PREFIX_SID_TLV_TYPE_ORIGINATOR_SRGB,
        BGP_PREFIX_SID_TLV_TYPE_DEPRECATED_4,
        BGP_PREFIX_SID_TLV_TYPE_SRV6_L3_SERVICE_TLV,
        BGP_PREFIX_SID_TLV_TYPE_SRV6_L2_SERVICE_TLV,
    };

    enum SRV6_SERVICE_SUB_TLV_TYPES {
        SRV6_SID_INFORMATION_SUB_TLV = 1,
    };

    enum SRv6_SERVICE_DATA_SUB_SUB_TLV_TYPES {
        SRV6_SID_STRUCTURE_SUB_SUB_TLV = 1,
    };
    /**
     * struct defines a generic TLV for the BGP Prefix-SID TLV (RFC8669 Section 3) its sub TLVs
     */
    struct generic_tlv {
        uint8_t        type;
        uint16_t       len;
        uint8_t        reserved;
        unsigned char  *data;
        unsigned char  *next_tlv = NULL;
    };
    typedef generic_tlv bgp_prefix_sid_tlv;
    typedef generic_tlv srv6_service_sub_tlv;
    typedef generic_tlv srv6_service_data_sub_sub_tlv;

    struct srv6_sid_structure_sub_sub_tlv {
        uint8_t  locator_block_length;
        uint8_t  locator_node_length;
        uint8_t  function_length;
        uint8_t  argument_length;
        uint8_t  transposition_length;
        uint8_t  transposition_offset;
    };

    struct srv6_sid_information_sub_tlv {
        unsigned char   sid_value[16];
        uint8_t         service_sid_flags;
        uint16_t        endpoint_behavior;
        unsigned char   reserved;
        srv6_sid_structure_sub_sub_tlv sid_structure;
    };
    
    /**
     * Constructor for class
     *
     * \details Handles bgp MP_REACH attributes
     *
     * \param [in]     logPtr                   Pointer to existing Logger for app logging
     * \param [in]     pperAddr                 Printed form of peer address used for logging
     * \param [in]     peer_info                Persistent Peer info pointer
     * \param [in]     enable_debug             Debug true to enable, false to disable
     */
    BGPPrefixSID(Logger *logPtr, std::string peerAddr, BMPReader::peer_info *peer_info, bool enable_debug=false);

    virtual ~BGPPrefixSID();

    void readData(u_char *field, u_char *data, size_t size, bool host_byte_order=true);
    void readData(uint16_t *field, u_char *data, size_t size=2, bool host_byte_order=true);

    const char* endpoint_behavior_str(uint16_t endpoint_behavior_code);

    /**
     * Parse the BGP Prefix-SID attribute data
     *
     * \details
     *      Will parse the BGP Prefix SID data passed.  Parsed data will be stored
     *      in parsed_data.
     *
     * \param [in]   attr_len       Length of the attribute data
     * \param [in]   data           Pointer to the attribute data
     * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
     *
     */
    void parseBGPPrefixSIDAttr(int attr_len, u_char *data, UpdateMsg::parsed_update_data &parsed_data);

    boost::property_tree::ptree parseSRv6L3ServiceTLV(int tlv_len, u_char *data);


private:
    bool                    debug;                  ///< debug flag to indicate debugging
    Logger                   *logger;               ///< Logging class pointer
    std::string             peer_addr;              ///< Printed form of the peer address for logging
    BMPReader::peer_info    *peer_info;

    // https://www.iana.org/assignments/segment-routing/segment-routing.xhtml
    inline const char* endpoint_behavior_codepoint_to_name(uint16_t code) {
        switch(code){
            case 0    : return "Reserved"; break;
            case 1    : return "End"; break;
            case 2    : return "End with PSP"; break;
            case 3    : return "End with USP"; break;
            case 4    : return "End with PSP & USP"; break;
            case 5    : return "End.X"; break;
            case 6    : return "End.X with PSP"; break;
            case 7    : return "End.X with USP"; break;
            case 8    : return "End.X with PSP & USP"; break;
            case 9    : return "End.T"; break;
            case 10   : return "End.T with PSP"; break;
            case 11   : return "End.T with USP"; break;
            case 12   : return "End.T with PSP & USP"; break;
            case 13   : return "End.B6.Insert"; break;
            case 14   : return "End.B6.Encaps"; break;
            case 15   : return "End.BM"; break;
            case 16   : return "End.DX6"; break;
            case 17   : return "End.DX4"; break;
            case 18   : return "End.DT6"; break;
            case 19   : return "End.DT4"; break;
            case 20   : return "End.DT46"; break;
            case 21   : return "End.DX2"; break;
            case 22   : return "End.DX2V"; break;
            case 23   : return "End.DT2U"; break;
            case 24   : return "End.DT2M"; break;
            case 25   : return "Reserved"; break;
            case 26   : return "End.B6.Insert.Red"; break;
            case 27   : return "End.B6.Encaps.Red"; break;
            case 28   : return "End with USD"; break;
            case 29   : return "End with PSP & USD"; break;
            case 30   : return "End with USP & USD"; break;
            case 31   : return "End with PSP, USP & USD"; break;
            case 32   : return "End.X with USD"; break;
            case 33   : return "End.X with PSP & USD"; break;
            case 34   : return "End.X with USP & USD"; break;
            case 35   : return "End.X with PSP, USP & USD"; break;
            case 36   : return "End.T with USD"; break;
            case 37   : return "End.T with PSP & USD"; break;
            case 38   : return "End.T with USP & USD"; break;
            case 39   : return "End.T with PSP, USP & USD"; break;
            case 40   : return "End.MAP"; break;
            case 41   : return "End.Limit"; break;
            case 42   : return "End with NEXT-ONLY-CSID"; break;
            case 43   : return "End with NEXT-CSID"; break;
            case 44   : return "End with NEXT-CSID & PSP"; break;
            case 45   : return "End with NEXT-CSID & USP"; break;
            case 46   : return "End with NEXT-CSID, PSP & USP"; break;
            case 47   : return "End with NEXT-CSID & USD"; break;
            case 48   : return "End with NEXT-CSID, PSP & USD"; break;
            case 49   : return "End with NEXT-CSID, USP & USD"; break;
            case 50   : return "End with NEXT-CSID, PSP, USP & USD"; break;
            case 51   : return "End.X with NEXT-ONLY-CSID"; break;
            case 52   : return "End.X with NEXT-CSID"; break;
            case 53   : return "End.X with NEXT-CSID & PSP"; break;
            case 54   : return "End.X with NEXT-CSID & USP"; break;
            case 55   : return "End.X with NEXT-CSID, PSP & USP"; break;
            case 56   : return "End.X with NEXT-CSID & USD"; break;
            case 57   : return "End.X with NEXT-CSID, PSP & USD"; break;
            case 58   : return "End.X with NEXT-CSID, USP & USD"; break;
            case 59   : return "End.X with NEXT-CSID, PSP, USP & USD"; break;
            case 60   : return "End.DX6 with NEXT-CSID"; break;
            case 61   : return "End.DX4 with NEXT-CSID"; break;
            case 62   : return "End.DT6 with NEXT-CSID"; break;
            case 63   : return "End.DT4 with NEXT-CSID"; break;
            case 64   : return "End.DT46 with NEXT-CSID"; break;
            case 65   : return "End.DX2 with NEXT-CSID"; break;
            case 66   : return "End.DX2V with NEXT-CSID"; break;
            case 67   : return "End.DT2U with NEXT-CSID"; break;
            case 68   : return "End.DT2M with NEXT-CSID"; break;
            case 69   : return "End.M.GTP6.D"; break;
            case 70   : return "End.M.GTP6.Di"; break;
            case 71   : return "End.M.GTP6.E"; break;
            case 72   : return "End.M.GTP4.E"; break;
            case 73   : return "End.DTM"; break;
            case 74   : return "End.M (Mirror SID)"; break;
            case 75   : return "End.Replicate"; break;
            case 76   : return "End.DTMC4"; break;
            case 77   : return "End.DTMC6"; break;
            case 78   : return "End.DTMC46"; break;
            case 79   : return "End.BXC"; break;
            case 80   : return "End.BXC with PSP"; break;
            case 81   : return "End.BXC with USP"; break;
            case 82   : return "End.BXC with USD"; break;
            case 83   : return "End.BXC with PSP, USP & USD"; break;
            case 100  : return "End.PSID"; break;
            case 101  : return "End with REPLACE-CSID"; break;
            case 102  : return "End with REPLACE-CSID & PSP"; break;
            case 103  : return "End with REPLACE-CSID & USP"; break;
            case 104  : return "End with REPLACE-CSID, PSP & USP"; break;
            case 105  : return "End.X with REPLACE-CSID"; break;
            case 106  : return "End.X with REPLACE-CSID & PSP"; break;
            case 107  : return "End.X with REPLACE-CSID & USP"; break;
            case 108  : return "End.X with REPLACE-CSID, PSP & USP"; break;
            case 109  : return "End.T with COC"; break;
            case 110  : return "End.T with PSP&COC"; break;
            case 112  : return "End.T with PSP&USP&COC"; break;
            case 128  : return "End with REPLACE-CSID & USD"; break;
            case 129  : return "End with REPLACE-CSID, USP & USD"; break;
            case 130  : return "End with REPLACE-CSID, PSP & USD"; break;
            case 131  : return "End with REPLACE-CSID, PSP, USP & USD"; break;
            case 132  : return "End.X with REPLACE-CSID & USD"; break;
            case 133  : return "End.X with REPLACE-CSID, PSP & USD"; break;
            case 134  : return "End.X with REPLACE-CSID, USP & USD"; break;
            case 135  : return "End.X with REPLACE-CSID, PSP, USP & USD"; break;
            case 137  : return "End.T with PSP&USD&COC"; break;
            case 139  : return "End.T with PSP&USP&USD&COC"; break;
            case 150  : return "End.XU"; break;
            case 151  : return "End.XU with PSP"; break;
            case 152  : return "End.XU with USP"; break;
            case 153  : return "End.XU with USD"; break;
            case 154  : return "End.XU with PSP, USP & USD"; break;
            case 155  : return "End.XU with REPPLACE-CSID"; break;
            case 156  : return "End.XU with REPPLACE-CSID & PSP"; break;
            case 157  : return "End.XU with REPPLACE-CSID & PSP & USP & USD"; break;
            case 32767: return "The SID defined in [RFC8754]"; break;
            case 65535: return "Opaque"; break;
        }
        if(32768 <= code && code <= 34815) {
            return "Reserved for Private Use";
        } else if (34816 <= code && code <= 65534) {
            return "Reserved";
        }
        return "Unassigned";
    }
};

} /* namespace bgp_msg */

#endif /* BGPPREFIXSID_H_ */
